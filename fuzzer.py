# -*- coding: utf-8 -*-
from pydbg import *
from pydbg.defines import *

import utils
import random
import sys
import threading
import os
import shutil
import time

class file_fuzzer:
    
    def __init__(self, exe_path, ext):

        self.exe_path           = exe_path
        self.ext                = ext
        self.orig_file          = None
        self.mutated_file       = None
        self.iteration        = 0
        self.crash              = None
        self.send_notify        = False
        self.pid                = None
        self.in_accessv_handler = False
        self.dbg                = None
        self.running            = False
        self.ready              = False
        self.test_cases = [ "\x41", "\xff", "\x00"]

    # 파일 선택
    def file_picker(self):
        #
        # 예외처리 할 것 들 
        #
        # 1. 디렉토리가 없으면 생성  
        # 2. 디렉토리안에 파일이 있는지 검사
        #
        file_list = os.listdir("input")
        list_length = len(file_list)
        file = file_list[random.randint(0, list_length-1)]
        shutil.copy("input\\%s" % file, "tmp\\%d.%s" % (self.iteration, self.ext))
        return file

    def fuzz(self):

        while 1:
            if not self.running:

                # 먼저 변형을 가할 파일을 선택한다.
                self.test_file = self.file_picker()
                self.mutate_file()

                # 디버거 쓰레드 실행
                pydbg_thread = threading.Thread(target=self.start_debugger)
                pydbg_thread.setDaemon(0)
                pydbg_thread.start()

                while self.pid == None:
                    time.sleep(1)

                # 모니터링 쓰레드 실행
                monitor_thread = threading.Thread(target=self.monitor_debugger)
                monitor_thread.setDaemon(0)
                monitor_thread.start()

                self.iteration +=1
            else:
                time.sleep(1)


    # 대상 어플리케이션을 실행시키는 디버거 쓰레드
    def start_debugger(self):

        print "[*] Starting debugger for iteration: %d" % self.iteration
        self.running = True
        self.dbg = pydbg()

        self.dbg.set_callback(EXCEPTION_ACCESS_VIOLATION,self.check_accessv)
        pid = self.dbg.load(self.exe_path,"tmp\\%d.%s" % (self.iteration, self.ext))

        self.pid = self.dbg.pid
        self.dbg.run()


    # 어플레킹션을 몇 초 동안 실행 되게 한 다음 종료시키는 모니터링 쓰레드 
    def monitor_debugger(self):

        counter = 0
        print "[*] Monitor thread for pid: %d waiting." % self.pid,
        while counter < 3:
            time.sleep(1)
            print counter,
            counter += 1
        print "\n\n"
        if self.in_accessv_handler != True:
            time.sleep(1)
            self.dbg.terminate_process()
            self.pid = None
            self.running = False
        else:
            print "[*] The access violation handler is doing its business. Going to sleep"           

            while self.running:
                time.sleep(1)

    # 에러를 추적하고 정보를 저장하기 위한 접근 위반 핸들러 
    def check_accessv(self,dbg):

        if dbg.dbg.u.Exception.dwFirstChance:

            return DBG_CONTINUE

        print "[*] Woot! Handling an access violation!"
        self.in_accessv_handler = True
        crash_bin = utils.crash_binning.crash_binning()
        crash_bin.record_crash(dbg)
        self.crash = crash_bin.crash_synopsis()

        # 에러 정보를 작성한다.
        crash_fd = open("crash\\crash-%d" % self.iteration,"w")
        crash_fd.write(self.crash)

        # 파일을 백업한다.
        shutil.copy("tmp\\%d.%s" % (self.iteration,self.ext),"crash\\%d.%s" % (self.iteration,self.ext))
        shutil.copy("input\\%s" % self.test_file,"crash\\%d_orig.%s" % (self.iteration,self.ext))

        self.dbg.terminate_process()
        self.in_accessv_handler = False
        self.running = False
            
        return DBG_EXCEPTION_NOT_HANDLED


    def mutate_file( self ):

        fd = open("tmp\\%d.%s" % (self.iteration, self.ext), "r+b")
        stream = fd.read()

        # 반복 횟수 랜덤 설정 
        count = random.randint(100)
        # 테스트 케이스 중에 하나를 고른다
        test_case = self.test_cases[random.randint(0,len(self.test_cases)-1)]

        for i in range(count):
            stream_length = len(stream)
            rand_offset   = random.randint(0,  stream_length - 1 )
            rand_len      = random.randint(1, 1000)

            print "Mutated : offset[%d] , %x , %d bytes" %(rand_offset, ord(test_case), rand_len)
            # 테스트 케이스 반복
            mutate = test_case * rand_len
            # 저장
            fd.seek(rand_offset)
            fd.write(mutate)

        #닫기
        fd.close()


        return

if __name__ == "__main__":

    print "[*] File Fuzzer."

    exe_path = "C:\\Program Files\\Hnc\\Hwp80\\Hwp.exe"
    ext      = "hwp"

    if exe_path is not None and ext is not None:
        fuzzer = file_fuzzer( exe_path, ext)
        fuzzer.fuzz()
    else:
        "[+] Error!"
