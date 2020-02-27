#include"stdafx.h"
#include<Windows.h>
#include"udis86.h" //디스어셈블링을 위한 udis86.h
#pragmacomment(lib,"libudis86.lib")//udis86의 라이브러리 파일

intsj_disassembler(unsignedchar*buff, char*out, intsize) {
	//기계어를 분해하는 역할을 담당한다. 여기서 udis86의 기능이 사용되게 된다.
	ud_t ud_obj;
	ud_init(&ud_obj);
	ud_set_input_buffer(&ud_obj, buff, 32);
	ud_set_mode(&ud_obj, 32);
	ud_set_syntax(&ud_obj, UD_SYN_INTEL);
	if(ud_disassemble(&ud_obj)) {
		sprintf_s(out, size, "%14s %s",ud_insn_hex(&ud_obj), ud_insn_asm(&ud_obj));
	} else {
		return-1;
	}
	return(int)ud_insn_len(&ud_obj);
}

intexception_debug_event(DEBUG_EVENT *pde) {
	//exception이 발생하면 실행되며, 밑의 함수들을 호출
	/* Open Process,ReadProcessMemory, OpenThread, GetThreadContext, SetThreadContext */
	// 이 함수와 WriteProcessMemory number 는 다른 프로세스에 access 하는데 필요
	DWORD dwReadBytes;
	HANDLE process_hander= OpenProcess( //프로세스 열기 , 헨들러에 할당 PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION, FALSE, pde->dwProcessId);
	if(!process_hander) return-1;
	HANDLE thread_handler= OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, pde->dwThreadId);
	//Open Thread : Register 정보 읽기위해 필요한 function
	if(!thread_handler) return-1;
	CONTEXT ctx;
	ctx.ContextFlags= CONTEXT_ALL;
	// related CONTEXT Thread
	GetThreadContext(thread_handler, &ctx);
	//GetThreadContext 통해레지스터를 Read 할 수 있다.
	charasm_string[256];
	unsignedcharasm_code[32];
	ReadProcessMemory(process_hander, (VOID *)ctx.Eip, asm_code, 32, &dwReadBytes);
	//exeception_debug_event 함수에서 exception이 발생할때 실행 된 명령을 얻기 위해 필요
	if(sj_disassembler(asm_code, asm_string, sizeof(asm_string)) == -1)
	asm_string[0] = '\0';
	printf("Exception: %08x (PID:%d, TID:%d)\n",
	pde->u.Exception.ExceptionRecord.ExceptionAddress,
	pde->dwProcessId, pde->dwThreadId);
	printf("%08x: %s\n",ctx.Eip, asm_string);
	printf(" Reg: EAX=%08x ECX=%08x EDX=%08x EBX=%08x\n",
	ctx.Eax, ctx.Ecx, ctx.Edx, ctx.Ebx);
	printf("	ESI=%08x EDI=%08x ESP=%08x EBP=%08x\n",
	ctx.Esi, ctx.Edi, ctx.Esp, ctx.Ebp);
	SetThreadContext(thread_handler, &ctx);
	//SetThreadContext를 통해레지스터를 Write 할 수 있다.
	CloseHandle(thread_handler);
	CloseHandle(process_hander);
	return0;
}
//End of exception_debug_event

inttmain(intargc, _TCHAR* argv[]) {
	STARTUPINFO startup_info;
	PROCESS_INFORMATION process_info;
	if(argc < 2) {
		fprintf(stderr, "C:\\>%s <sample.exe>\n",argv[0]);
		//Usage example output return1;
	}
	// 생성될프로세스의정보가저장될구조체를선언
	memset(&process_info, 0, sizeof(process_info));
	//startup_info 구조체의 정보를 명시
	memset(&startup_info, 0, sizeof(startup_info));
	startup_info.cb= sizeof(STARTUPINFO);
	BOOL r = CreateProcess( //Create the Process
	NULL, argv[1], NULL, NULL, FALSE,
	NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED | DEBUG_PROCESS, NULL, NULL, &startup_info, &process_info);
	if(!r)
	return-1;
	/*=====BOOL return 함수의 경우 return 0; 와 겹쳐 ERROR 가 나므로 이름을 r 로 변경========*/
	ResumeThread(process_info.hThread);
	intprocess_counter = 0;
	//프로세스 카운터 선언
	do {
		DEBUG_EVENT dbg_event;
		if(!WaitForDebugEvent(&dbg_event, INFINITE)) break;
		DWORD dwContinueStatus = DBG_CONTINUE;
		//EXCEPTION_DEBUG_EVENT 발생시디버거에서직접예외를처리
		switch(dbg_event.dwDebugEventCode) //디버그 이벤트 유형으로 Switch Case 를 나눔 {
			caseCREATE_PROCESS_DEBUG_EVENT:
			process_counter++;
			break;
			caseEXIT_PROCESS_DEBUG_EVENT:
			process_counter--;
			break;
			caseEXCEPTION_DEBUG_EVENT:
			if(dbg_event.u.Exception.ExceptionRecord.ExceptionCode !=
			EXCEPTION_BREAKPOINT) {
				dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
			}
			exception_debug_event(&dbg_event);
			//execption_debug_event 함수 에서 레지스터 값을 다시 쓸 필요가 없으므로
			// SetThreadContext 함수를 호출 할 필요가 없어지게 된다.
			break;
		}
		ContinueDebugEvent(
		dbg_event.dwProcessId, dbg_event.dwThreadId, dwContinueStatus);
	}
	while(process_counter > 0);
	CloseHandle(process_info.hThread);
	//Thread 종료
	CloseHandle(process_info.hProcess);
	//Process 종료
	return0;
}
