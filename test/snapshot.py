# -*- coding: cp949 -*-
# snapshot.py 

from pydbg import *
from pydbg.defines import *

import threading
import time
import sys

class snapshotter(object):
    def  __init__(self,exe_path):

        self.exe_path = exe_path # �����θ� �����ϴ� ���� 
        self.pid = None 
        self.dbg = None 
        self.running = True # �����尡 �����ϰ��ִ��� ����


        ##############################################
        #               ù��° �ܰ�                    #
        ##############################################
        # ����� �����带 ���۽�Ű��,
        # ��� ���μ����� PID�� ������ ������ ������ ����.
        pydbg_thread = threading.Thread(target=self.start_debugger)
        # self.start_debugger �� �����ϴ� ������ ���� 
        pydbg_thread.setDaemon(0) # �� �����尡 ���� ���������� �ƴ��� ��Ÿ���� ��
        pydbg_thread.start() # ������ ����

        while self.pid == None:
            time.sleep(1)


        ##############################################
        #                �ι�° �ܰ�                   #
        ##############################################
        # ������ PID�� ������ �����̰� ��� ���μ����� ���� ���̴�.
        # �������� ���� �� ���� �����带 �����Ų��.
        monitor_thread = threading.Thread(target=self.monitor_debugger)
        monitor_thread.setDaemon(0)
        monitor_thread.start()


    ########################################
    #             ����° �ܰ�                #
    ########################################
    def monitor_debugger(self):

        while self.running == True: # ����� ��� ���μ����� �������̶��

            input = raw_input("Enter: 'snap','restore' or 'quit'") 
            input = input.lower().strip()
            #lower:�빮��->�ҹ���
            #strip:���� ����

            if input == 'quit': # �Է��� ���ڰ� quit ���
                print '[*] Exiting the snapshotter.'
                self.running = False
                self.dbg.terminate_process() #PyDbg ��ü �����ִ�
                #terminate_process �� ���μ����� �����Ű�� �ֹ��̴�.

            elif input == 'snap': # �Է��� ���ڰ� snap �̶��

                print '[*] Suspending all threads.'
                # �������� ���ϱ� ���ؼ���
                # ����ǰ� �ִ� ��� �����带 �������Ѿ� �Ѵ�.
                # �׷��߸� �������� ���ϰ� �ִ� ���� �����Ϳ� ����������
                # ������� �ʱ� �����̴�. 
                self.dbg.suspend_all_threads()
                # PyDbg ���� ��� �����带 �Ͻ����� ��Ű�� ���ؼ�
                # ����ϴ� �Լ��� suspend_all_threads() �Լ��̴�.

                print '[*] obtaining snapshot.'
                self.dbg.process_snapshot()
                # process_snaphot : �������� ���ϴµ� ���Ǵ� �Լ� 
                # �ڼ��� ������ ������ ���� �ϵ��� �ϰڽ��ϴ�.
                
                print '[*] Resuming operation.'
                self.dbg.resume_all_threads()
                # ���μ����� �Ͻ����� ��Ű�� �������� ���ߴٸ�
                # �ٽ� ����� �����־�� �Ѵ�.

            elif input == 'restore':
                print '[*] Suspending all threads.'
                self.dbg.suspend_all_threads()

                print '[*] restoring snapshot'
                self.dbg.process_restore()

                print '[*] resuming operation.'
                self.dbg.resume_all_threads()
        #########################################
        #              �׹�° �ܰ�                #  
        #########################################
    def start_debugger(self):
        self.dbg = pydbg()
        pid = self.dbg.load(exe_path)
        self.pid = self.dbg.pid
        self.dbg.run()

       


#####################################
#           �ټ���° �ܰ�             #
#####################################
    
#exe_path = 'c:\\WINDOWS\\System32\\calc.exe'
exe_path = 'c:\\WINDOWS\\System32\\notepad.exe'
snapshotter(exe_path)



                    
