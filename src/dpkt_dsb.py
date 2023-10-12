import dpkt.pcapng as dpng
import dpkt

PCAPNG_BT_DSB = 0x0000000A  # Decryption Secret Block


class DecryptionSecretBlock(dpng._PcapngBlock):
    """Decryption Secret block"""

    __hdr__ = (
        ('type', 'I', PCAPNG_BT_DSB),
        ('len', 'I', 12),
        ('secrets_type', 'I', 4),
        ('secrets_length', 'I', 4),
        # (secrets data, variable size),
        # (options, variable size),
        ('_len', 'I', 4)
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        if self.len > len(buf):
            raise dpkt.NeedData

        # packet data
        po = self.__hdr_len__ - 4  # offset of pkt_data
        self.pkt_data = buf[po:po + self.secrets_length]

        # skip padding between pkt_data and options
        opts_offset = po + dpng._align32b(self.secrets_length)
        self._do_unpack_options(buf, opts_offset)

    def __bytes__(self):
        pkt_buf = self.pkt_data

        pkt_len = len(pkt_buf)
        self.secrets_length = pkt_len
        self.pkt_len = pkt_len

        opts_buf = self._do_pack_options()

        n = self.__hdr_len__ + dpng._align32b(self.secrets_length) + len(opts_buf)
        self.len = n
        self._len = n

        hdr_buf = self._pack_hdr(
            self.type,
            n,
            self.secrets_type,
            self.secrets_length,
            n
        )

        return b''.join([hdr_buf[:-4], dpng._padded(pkt_buf), opts_buf, hdr_buf[-4:]])

    def __len__(self):
        opts_len = sum(len(o) for o in self.opts)
        return self.__hdr_len__ + dpng._align32b(self.caplen) + opts_len


class DecryptionSecretBlockLE(DecryptionSecretBlock):
    __byte_order__ = '<'


class Reader(object):
    """Simple pypcap-compatible pcapng file reader."""

    def __init__(self, fileobj):
        self.name = getattr(fileobj, 'name', '<{0}>'.format(fileobj.__class__.__name__))
        self.__f = fileobj

        shb = dpng.SectionHeaderBlock()
        buf = self.__f.read(shb.__hdr_len__)
        if len(buf) < shb.__hdr_len__:
            raise ValueError('invalid pcapng header')

        # unpack just the header since endianness is not known
        shb.unpack_hdr(buf)
        if shb.type != dpng.PCAPNG_BT_SHB:
            raise ValueError('invalid pcapng header: not a SHB')

        # determine the correct byte order and reload full SHB
        if shb.bom == dpng.BYTE_ORDER_MAGIC_LE:
            self.__le = True
            buf += self.__f.read(dpng._swap32b(shb.len) - shb.__hdr_len__)
            shb = dpng.SectionHeaderBlockLE(buf)
        elif shb.bom == dpng.BYTE_ORDER_MAGIC:
            self.__le = False
            buf += self.__f.read(shb.len - shb.__hdr_len__)
            shb = dpng.SectionHeaderBlock(buf)
        else:
            raise ValueError('unknown endianness')

        # check if this version is supported
        if shb.v_major != dpng.PCAPNG_VERSION_MAJOR:
            raise ValueError('unknown pcapng version {0}.{1}'.format(shb.v_major, shb.v_minor, ))

        # look for a mandatory IDB
        idb = None
        while 1:
            buf = self.__f.read(8)
            if len(buf) < 8:
                break

            blk_type, blk_len = dpng.struct_unpack('<II' if self.__le else '>II', buf)
            buf += self.__f.read(blk_len - 8)

            if blk_type == dpng.PCAPNG_BT_IDB:
                idb = (dpng.InterfaceDescriptionBlockLE(buf) if self.__le
                       else dpng.InterfaceDescriptionBlock(buf))
                break
            # just skip other blocks

        if idb is None:
            raise ValueError('IDB not found')

        # set timestamp resolution and offset
        self._divisor = float(1e6)  # defaults
        self._tsoffset = 0
        for opt in idb.opts:
            if opt.code == dpng.PCAPNG_OPT_IF_TSRESOL:
                # if MSB=0, the remaining bits is a neg power of 10 (e.g. 6 means microsecs)
                # if MSB=1, the remaining bits is a neg power of 2 (e.g. 10 means 1/1024 of second)
                opt_val = dpng.struct_unpack('b', opt.data)[0]
                pow_num = 2 if opt_val & 0b10000000 else 10
                self._divisor = float(pow_num ** (opt_val & 0b01111111))

            elif opt.code == dpng.PCAPNG_OPT_IF_TSOFFSET:
                # 64-bit int that specifies an offset (in seconds) that must be added to the
                # timestamp of each packet
                self._tsoffset = dpng.struct_unpack('<q' if self.__le else '>q', opt.data)[0]

        if idb.linktype in dpng.dltoff:
            self.dloff = dpng.dltoff[idb.linktype]
        else:
            self.dloff = 0

        self.__f.seek(0)

        self.idb = idb
        self.snaplen = idb.snaplen
        self.filter = ''
        self.__iter = iter(self)

    @property
    def fd(self):
        return self.__f.fileno()

    def fileno(self):
        return self.fd

    def datalink(self):
        return self.idb.linktype

    def setfilter(self, value, optimize=1):
        raise NotImplementedError

    def readpkts(self):
        return list(self)

    def __next__(self):
        return next(self.__iter)

    next = __next__  # Python 2 compat

    def dispatch(self, cnt, callback, *args):
        """Collect and process packets with a user callback.

        Return the number of packets processed, or 0 for a savefile.

        Arguments:

        cnt      -- number of packets to process;
                    or 0 to process all packets until EOF
        callback -- function with (timestamp, pkt, *args) prototype
        *args    -- optional arguments passed to callback on execution
        """
        processed = 0
        if cnt > 0:
            for _ in range(cnt):
                try:
                    ts, pkt = next(iter(self))
                except StopIteration:
                    break
                callback(ts, pkt, *args)
                processed += 1
        else:
            for ts, pkt in self:
                callback(ts, pkt, *args)
                processed += 1
        return processed

    def loop(self, callback, *args):
        self.dispatch(0, callback, *args)

    def __iter__(self):
        self.__f.seek(0)
        while 1:
            buf = self.__f.read(8)
            if len(buf) < 8:
                break

            blk_type, blk_len = dpng.struct_unpack('<II' if self.__le else '>II', buf)
            buf += self.__f.read(blk_len - 8)

            if blk_type == dpng.PCAPNG_BT_EPB:
                epb = dpng.EnhancedPacketBlockLE(buf) if self.__le else dpng.EnhancedPacketBlock(buf)
                ts = self._tsoffset + (((epb.ts_high << 32) | epb.ts_low) / self._divisor)
                yield ts, epb.pkt_data
            elif blk_type == dpng.PCAPNG_BT_PB:
                pb = dpng.PacketBlockLE(buf) if self.__le else dpng.PacketBlock(buf)
                ts = self._tsoffset + (((pb.ts_high << 32) | pb.ts_low) / self._divisor)
                yield ts, pb.pkt_data
            elif blk_type == PCAPNG_BT_DSB:
                dsb = DecryptionSecretBlockLE(buf) if self.__le else DecryptionSecretBlock(buf)
                ts = -1
                yield ts, dsb.pkt_data

            # just ignore other blocks
