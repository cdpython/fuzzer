# -*- coding: cp949 -*-
from ctypes import *
from define import *

kernel32 = windll.kernel32

class debugger():
    def __init__(self):
        pass

    def load(self,path_to_exe):

        # dwCreation �÷��׸� �̿��ؼ� ���μ����� ��� ������ ������ �Ǵ��Ѵ�.
        # ������ GUI�� ������ �Ѵٸ� creation_flags��
        # CREATE_NEW_CONSOLE�� �����ϸ� �ȴ�.
        creation_flags = DEBUG_PROCESS

        # ����ü �ν��Ͻ�ȭ
        startupinfo         = STARTUPINFO()
        process_information = PROCESS_INFORMATION()

        # ���� �� �ɼ��� ���μ����� �������� â���� ����ǰ� ������ش�.
        # �̴� STARTUPINFO struct ����ü�� ���� ���뿡 ���� ����� �Ƿμ�����
        # � ������ �ִ��� �����ش�.
        startupinfo.dwFlags     = 0x1
        startupinfo.wShoWindow  = 0x0

        #�������� STARTUPINFO struct ����ü�� �ڽ��� ũ�⸦ ��Ÿ���� cb ���� ���� �ʱ�ȭ
        startupinfo.cb = sizeof(startupinfo)

        if kernel32.CreateProcessA(path_to_exe,
                                   None,
                                   None,
                                   None,
                                   None,
                                   creation_flags,
                                   None,
                                   None,
                                   byref(startupinfo),
                                   byref(process_information)):
            print "[+] Success to launched the Process!"
            print "[+] PID : %d" % process_information.dwProcessId
        else:
            print "[+] Error: 0x%08x." % kernel32.GetLastError()
