from unittest import TestCase
import os
import subprocess


class TestProg(TestCase):
    def setUp(self) -> None:
        self.files = os.listdir(os.getcwd() + "/testfiles")

        self.lorem_files = os.listdir(os.getcwd() + "/incomplete_pcaps")

    def testrun(self):
        for file in self.files:
            res = subprocess.run(
                ["python3", "../tlexport/main.py", "-i", "./testfiles/" + file, "-s",
                 "./keylog.log", "-d", "INFO", "-p","443", "44330","5556"], capture_output=True, text=True)

            self.assertIn("Lorem\\n", res.stderr, msg="\n" + file)
            self.assertIn(
                "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua.",
                res.stderr, msg="\n" + file)

        for file in self.lorem_files:
            res = subprocess.run(
                ["python3", "../tlexport/main.py", "-i", "./incomplete_pcaps/" + file, "-s", "./keylog.log", "-d", "INFO", "-p","443", "44330","5556"],
                capture_output=True, text=True)
            self.assertIn("Lorem\\n", res.stderr, msg="\n" + file)
