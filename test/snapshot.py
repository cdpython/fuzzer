# -*- coding: cp949 -*-
# snapshot.py 

from pydbg import *
from pydbg.defines import *

import threading
import time
import sys

class snapshotter(object):
    def  __init__(self,exe_path):

        self.exe_path = exe_path # 실행경로를 저장하는 변수 
        self.pid = None 
        self.dbg = None 
        self.running = True # 쓰레드가 실행하고있는지 여부


        ##############################################
        #               첫번째 단계                    #
        ##############################################
        # 디버거 스레드를 시작시키고,
        # 대상 프로세스의 PID가 설정될 때까지 루프를 돈다.
        pydbg_thread = threading.Thread(target=self.start_debugger)
        # self.start_debugger 를 실행하는 쓰레드 생성 
        pydbg_thread.setDaemon(0) # 이 쓰레드가 데몬 쓰레드인지 아닌지 나타내는 값
        pydbg_thread.start() # 쓰레드 시작

        while self.pid == None:
            time.sleep(1)


        ##############################################
        #                두번째 단계                   #
        ##############################################
        # 지금은 PID가 설정된 상태이고 대상 프로세스가 실행 중이다.
        # 스냅샷을 위한 두 번쨰 스레드를 실행시킨다.
        monitor_thread = threading.Thread(target=self.monitor_debugger)
        monitor_thread.setDaemon(0)
        monitor_thread.start()


    ########################################
    #             세번째 단계                #
    ########################################
    def monitor_debugger(self):

        while self.running == True: # 디버깅 대상 프로세스가 실행중이라면

            input = raw_input("Enter: 'snap','restore' or 'quit'") 
            input = input.lower().strip()
            #lower:대문자->소문자
            #strip:공백 제거

            if input == 'quit': # 입력한 문자가 quit 라면
                print '[*] Exiting the snapshotter.'
                self.running = False
                self.dbg.terminate_process() #PyDbg 객체 내에있는
                #terminate_process 는 프로세스를 종료시키는 핫무이다.

            elif input == 'snap': # 입력한 문자가 snap 이라면

                print '[*] Suspending all threads.'
                # 스냅샷을 구하기 위해서는
                # 실행되고 있는 모든 쓰레드를 중지시켜야 한다.
                # 그래야만 스냅샷을 구하고 있는 도중 데이터와 상태정보가
                # 변경되지 않기 때문이다. 
                self.dbg.suspend_all_threads()
                # PyDbg 에서 모든 쓰레드를 일시중지 시키기 위해서
                # 사용하는 함수는 suspend_all_threads() 함수이다.

                print '[*] obtaining snapshot.'
                self.dbg.process_snapshot()
                # process_snaphot : 스냅샷을 구하는데 사용되는 함수 
                # 자세한 설명은 본문을 통해 하도록 하겠습니다.
                
                print '[*] Resuming operation.'
                self.dbg.resume_all_threads()
                # 프로세스를 일시중지 시키고 스냅샷을 구했다면
                # 다시 재실행 시켜주어야 한다.

            elif input == 'restore':
                print '[*] Suspending all threads.'
                self.dbg.suspend_all_threads()

                print '[*] restoring snapshot'
                self.dbg.process_restore()

                print '[*] resuming operation.'
                self.dbg.resume_all_threads()
        #########################################
        #              네번째 단계                #  
        #########################################
    def start_debugger(self):
        self.dbg = pydbg()
        pid = self.dbg.load(exe_path)
        self.pid = self.dbg.pid
        self.dbg.run()

       


#####################################
#           다섯번째 단계             #
#####################################
    
#exe_path = 'c:\\WINDOWS\\System32\\calc.exe'
exe_path = 'c:\\WINDOWS\\System32\\notepad.exe'
snapshotter(exe_path)



                    
