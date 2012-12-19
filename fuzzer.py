# -*- coding: utf-8 -*-
from pydbg import *
from pydbg.defines import *

import utils
import random
import threading
import os
import shutil
import time


class file_fuzzer:
    def __init__(self, exe_path):
        self.mutate_count       = 50
        self.mutate_list            = []
        self.selected_list          = [] # 크래시 트래킹에 사용할 리스트
        self.exe_path           = exe_path
        self.ext            = ".hwp"
        self.orig_file          = None
        self.sample_dir         = "sample\\"
        self.tmp_file           = None
        self.tmp_dir            = "tmp\\"
        self.count          = 0
        self.crash          = None
        self.crash_tracking = False # 크래시 추적 활성화 체크
        self.crash_tracking_step = 0 # 크래시 추적 단계 설정
        self.crash_again    = False # 크래시 여부 체크
        self.pivot            = None # 랜덤 인덱스 저장을 위한 변수
        self.crash_count = None # 크래시 번호 저장
        self.check          = False
        self.pid            = None
        self.in_accessv_handler     = False
        self.dbg            = None
        self.running            = False

    # 파일 선택
    def file_picker(self):
        file_list = os.listdir(self.sample_dir)
        self.tmp_file = self.tmp_dir+ "test.hwp"
        self.orig_file = self.sample_dir+random.choice(file_list)
        shutil.copy(self.orig_file,  self.tmp_file)
        return

    def fuzz(self):

        while 1:

            while self.running :
                time.sleep(1)

            self.running = True

            print "[*] Starting debugger for iteration: %d" % self.count

            # 크래시 추적 활성화 여부 체크
            if self.crash_tracking == False:
                # 먼저 변형을 가할 파일을 선택한다.
                self.file_picker()
                self.mutate_file()
            else: #크래시 추적이 활성화 되었으면
                
                # 크래시 난 파일 복사
                shutil.copy(self.orig_file,  self.tmp_file)
                # 트래킹하는 뮤테이션 함수 호출
                self.mutate_track()

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

        self.running = True
        self.dbg = pydbg()

        self.dbg.set_callback(EXCEPTION_ACCESS_VIOLATION,self.check_accessv)
        pid = self.dbg.load(self.exe_path, self.tmp_file)

        self.pid = self.dbg.pid
        self.dbg.run()


    # 어플레킹션을 몇 초 동안 실행 되게 한 다음 종료시키는 모니터링 쓰레드 
    def monitor_debugger(self):

        counter = 0
        print "[*] waiting ",
        while counter < 3:
            time.sleep(1)
            print ".",
            counter += 1
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
    def check_accessv(self, dbg):

        # 트래킹 활성화 여부 체크
        if self.crash_tracking == False:
            # 트래킹 활성화
            self.crash_tracking = True
            print "\n[*] Woot! Handling an access violation!"
            self.in_accessv_handler = True
            crash_bin = utils.crash_binning.crash_binning()
            crash_bin.record_crash(dbg)
            self.crash = crash_bin.crash_synopsis()

            # 크래시 일 때 카운트정보를 작성한다.
            self.crash_count = self.count
            # 크래시 정보 로깅
            crash_fd = open("crash\\crash-%d.log" % self.count,"w")
            crash_fd.write(self.crash)
            crash_fd.write("----------------- mutate log -------------------\n")
            for i in self.mutate_list:
                crash_fd.write("offset : ")
                crash_fd.write(hex(i[0]))
                crash_fd.write(", 0x"+i[1])
                crash_fd.write("\n")
            #crash_fd.write("\n\nEND")
            crash_fd.close()

            # 원본 파일을 백업한다.
            shutil.copy(self.orig_file,"crash\\%d_orig%s" % (self.count,self.ext))

            self.dbg.terminate_process()
            self.pid = None

            return DBG_EXCEPTION_NOT_HANDLED

        # 트래킹 활성화 시 수행할 루틴 
        else:
            print "[+] Crash Tracking..."

            self.crash_again = True

            self.dbg.terminate_process()
            self.pid = None

            return DBG_EXCEPTION_NOT_HANDLED


    def mutate_file( self ):

        print "[*] Selected file : %s" % self.orig_file

        self.mutate_list = []
        fd = open(self.tmp_file, "r+b")
        stream = fd.read()
        stream_length = len(stream)
        # 테스트 케이스 중에 하나를 고른다
        attack = ['\x00', '\x41', '\xff']

        for i in range(self.mutate_count):
            
            rand_offset   = random.randint(0,  stream_length - 1 )
            mutate = random.choice(attack)
            mutate = mutate * random.randint(1,4)

            self.mutate_list.append( (rand_offset, mutate.encode('hex')) )
            
            fd.seek(rand_offset)
            fd.write(mutate)

        fd.close()
        return

    def mutate_track( self ):

        # 뮤테이션 리스트 원소의 갯수가 5개보다 적으면 수행 할 루틴
        if len(self.mutate_list) < 5:
            print "[ ^^ ] tracking Finished! %d -> %d" % (self.mutate_count, len(self.mutate_list))
            # 크래시 파일 백업
            shutil.copy(self.tmp_file, "crash\\%d%s" % (self.crash_count,self.ext))

            f= open("crash\\%d%s" % (self.crash_count,self.ext),'r+b')
            for i in self.mutate_list:
                f.seek(i[0])
                f.write(chr(int(i[1][:2],16)) * (len(i[1])/2))
            f.close()
            # 각종 변수 초기화
            self.crash_tracking = False
            self.crash_again = False
            self.crash_tracking_step = 0
            self.selected_list = []
            self.pivot = 0
            # 로그 추가 기록
            f = open("crash\\crash-%d.log" % self.crash_count, 'a')
            f.write("\n\n---------------- Check this Offset!! ------------------\n\n")
            for i in self.mutate_list:
                f.write("offset : ")
                f.write(hex(i[0]))
                f.write(", 0x"+i[1])
                f.write("\n")
            f.write("\n\nEND")
            f.close()
            
            return


        # 수정할 파일 오픈 
        f = open(self.tmp_file, 'r+b')

        # 트래킹이 처음 스탭일때(0) 수행
        if self.crash_tracking_step == 0:
            # 랜덤한 피봇 설정
            self.pivot= self.mutate_list.index(random.choice(self.mutate_list))
            # 트래킹 스탭 1로 설정
            self.crash_tracking_step = 1

        # 크래시가 발생하면 수행할 루틴
        if self.crash_again == True:
            print "[+] crash Again!!"
            # 크래시 난 리스트를 뮤테이션 리스트에 넣는다.
            self.mutate_list = self.selected_list
            # 크래시가 나면 새로운 피봇 설정
            self.pivot = self.mutate_list.index(random.choice(self.mutate_list))
            self.check = False


        print "[*] tracking Selected file : %s" % self.orig_file
        print "[+] Mutate list %d" % len(self.mutate_list)

        #크래시가 안났으면 기존 피봇 사용
        pivot = self.pivot
        
        # 피봇을 기준으로 좌우로 나눈다.
        left = self.mutate_list[:pivot]
        right = self.mutate_list[pivot:]

        # 리스트 선택
        if self.check == False:
            print "left"
            self.selected_list = left
            #체크 변수 토글
            self.check = True
        else:
            print "right"
            self.selected_list = right
            #체크 변수 토글
            self.check = False
        
        #tmp 파일에 쓰기
        for i in self.selected_list:
            f.seek(i[0])
            f.write(chr(int(i[1][:2],16)) * (len(i[1])/2))
        f.close()
        # 크래시 체크 변수 off
        self.crash_again = False
        return

if __name__ == "__main__":

    print "[*] File Fuzzer."
    if os.path.exists("C:\\Program Files (x86)\\Hnc\\Hwp80\\Hwp.exe"):
        exe_path = "C:\\Program Files (x86)\\Hnc\\Hwp80\\Hwp.exe"
    else:
        exe_path = "C:\\Program Files\\Hnc\\Hwp80\\Hwp.exe"

    if exe_path is not None:
        fuzzer = file_fuzzer( exe_path)
        fuzzer.fuzz()
    else:
        "[+] Error!"
