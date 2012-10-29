# -*- coding: cp949 -*-
from ctypes import *
from define import *

kernel32 = windll.kernel32

class debugger():
    def __init__(self):
        pass

    def load(self,path_to_exe):

        # dwCreation 플래그를 이용해서 프로세스를 어떻게 생성할 것인지 판단한다.
        # 계산기의 GUI를 보고자 한다면 creation_flags를
        # CREATE_NEW_CONSOLE로 설정하면 된다.
        creation_flags = DEBUG_PROCESS

        # 구조체 인스턴스화
        startupinfo         = STARTUPINFO()
        process_information = PROCESS_INFORMATION()

        # 다음 두 옵션은 프로세스가 독립적인 창으로 실행되게 만들어준다.
        # 이는 STARTUPINFO struct 구조체의 설정 내용에 따라 디버기 피로세스에
        # 어떤 영향을 주는지 보여준다.
        startupinfo.dwFlags     = 0x1
        startupinfo.wShoWindow  = 0x0

        #다음에는 STARTUPINFO struct 구조체를 자신의 크기를 나타내는 cb 변수 값을 초기화
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
