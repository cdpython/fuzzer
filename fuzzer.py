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
    def __init__(self, exe_path):

        self.exe_path = exe_path
        self.ext = ".hwp"
        self.orig_file = None
        self.sample_dir  = "sample\\"
        self.tmp_file        = None
        self.tmp_dir = "tmp\\"
        self.count        = 0
        self.crash              = None
        self.pid                = None
        self.in_accessv_handler = False
        self.dbg                = None
        self.running            = False

    # 파일 선택
    def file_picker(self):
        file_list = os.listdir(self.sample_dir)
        self.tmp_file = self.tmp_dir+ `random.randint(0,3)`+self.ext
        self.orig_file = self.sample_dir+random.choice(file_list)
        shutil.copy(self.orig_file,  self.tmp_file)
        return

    def fuzz(self):

        while 1:

            while self.running :
                    time.sleep(1)

            self.running = True

            # 먼저 변형을 가할 파일을 선택한다.
            self.file_picker()
            self.mutate_file()

            # 디버거 쓰레드 실행
            pydbg_thread = threading.Thread(target=self.start_debugger)
            pydbg_thread.setDaemon(0)
            pydbg_thread.start()

            while self.pid == None:
                time.sleep(0.5)

            # 모니터링 쓰레드 실행
            monitor_thread = threading.Thread(target=self.monitor_debugger)
            monitor_thread.setDaemon(0)
            monitor_thread.start()

            self.count +=1



    # 대상 어플리케이션을 실행시키는 디버거 쓰레드
    def start_debugger(self):

        print "[*] Starting debugger for iteration: %d" % self.count
        self.running = True
        self.dbg = pydbg()

        self.dbg.set_callback(EXCEPTION_ACCESS_VIOLATION,self.check_accessv)
        pid = self.dbg.load(self.exe_path, self.tmp_file)

        self.pid = self.dbg.pid
        self.dbg.run()


    # 어플레킹션을 몇 초 동안 실행 되게 한 다음 종료시키는 모니터링 쓰레드 
    def monitor_debugger(self):

        counter = 0
        print "[*] waiting " % self.pid,
        while counter < 3:
            time.sleep(1)
            print "."
            counter += 1
        print "[*] countinue"
        print "\n"

        if self.in_accessv_handler != True:
            tid = c_ulong(0)
            if windll.kernel32.GetHandleInformation(self.dbg.h_process, byref(tid)) :
                self.dbg.terminate_process()
            self.dbg.close_handle(self.dbg.h_process)
            
        else:
            while self.pid != None:
                time.sleep(0.5)
        
        while True :
            try :
                os.remove(self.tmp_file)
                break
            except :
                time.sleep(0.2)

        self.in_accessv_handler = False
        self.running = False

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
        crash_fd = open("crash\\crash-%d.log" % self.count,"w")
        crash_fd.write(self.crash)

        # 파일을 백업한다.
        shutil.copy(self.tmp_file, "crash\\%d%s" % (self.count,self.ext))
        shutil.copy(self.orig_file,"crash\\%d_orig%s" % (self.count,self.ext))

        self.dbg.terminate_process()
        self.pid = None

        return DBG_EXCEPTION_NOT_HANDLED


    def mutate_file( self ):

        fd = open(self.tmp_file, "r+b")
        stream = fd.read()
        stream_length = len(stream)
        # 반복 횟수 랜덤 설정 
        count = random.randint(1,10)
        # 테스트 케이스 중에 하나를 고른다
        attack = ['\x00', '\x41', '\xff']
        mutate = random.choice(attack)

        for i in range(count):
            
            rand_offset   = random.randint(0,  stream_length - 1 )

            print "Mutated : offset[%d] , %x" %(rand_offset, ord(mutate))
            # 테스트 케이스 반복
            # 저장
            fd.seek(rand_offset)
            fd.write(mutate)

        #닫기
        fd.close()
        return

if __name__ == "__main__":

    print "[*] File Fuzzer."

    exe_path = "C:\\Program Files (x86)\\Hnc\\Hwp80\\Hwp.exe"
    ext      = "hwp"

    if exe_path is not None:
        fuzzer = file_fuzzer( exe_path)
        fuzzer.fuzz()
    else:
        "[+] Error!"
