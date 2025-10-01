from core import Expect, Filter, Input, accesslog, data, proc, sshlog, DirTraversal, NullByte, ZipWrapper
from core.utils import colors

def test_data(args):
    print(colors("[~] Testing with data:// ", 93))
    d = data.Data(args)
    d.execute_data()

def test_input(args):
    print(colors("[~] Testing with input:// ", 93))
    i = Input.Input(args)
    i.execute_input()

def test_expect(args):
    print(colors("[~] Testing with expect:// ", 93))
    e = Expect.Expect(args)
    e.execute_expect()

def test_proc(args):
    print(colors("[~] /proc/self/environ Technique Selected!", 93))
    i = proc.Environ(args)
    i.execute_environ()

def test_access(args):
    print(colors("[~] Testing for Apache access.log poisoning", 93))
    if not args.location:
        print(colors("[~] Log Location Not Provided! Using Default", 93))
        l = "/var/log/apache2/access.log"
    else:
        l = args.location
    a = accesslog.Logs(args)
    a.execute_logs()

def test_ssh(args):
    print(colors("[~] Testing for SSH log poisoning ", 93))
    if not args.location:
        print(colors("[~] Log Location Not Provided! Using Default", 93))
        l = "/var/log/auth.log"
    else:
        l = args.location
    a = sshlog.SSHLogs(args)
    a.execute_ssh()

def test_filter(args):
    print(colors("[~] Testing with filter://", 93))
    f = Filter.Filter(args)
    f.execute_filter()

def test_directory_traversal(args):
    print(colors("[~] Testing for directory traversal", 93))
    dt = DirTraversal.dirTraversal(args, True)
    dt.execute_dirTraversal()

def test_null_byte(args):
    print(colors("[~] Testing for Null Byte Poisoning", 93))
    nb = NullByte.NullByte(args)
    nb.execute_null_byte()

def test_zip_wrapper(args):
    print(colors("[~] Testing with ZIP wrapper", 93))
    zw = ZipWrapper.ZipWrapper(args)
    zw.execute_zip_wrapper()
