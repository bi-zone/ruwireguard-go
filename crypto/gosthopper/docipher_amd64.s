// ~=  GOSThopper  =~
// Kuznechik cipher, GOST R 34.12-2015
// Implementation of block level operations for amd64 platform.
//
// Author: Alexander Venedioukhin, dxdt.ru
// Date: 17/02/2019
// Free software, distribution unlimited.

TEXT ·DoEncrypt(SB), $0-176
// Encrypts block.
		MOVOU	pt+8(SP), X0				// PT (Plain Text), source.
		LEAQ	rk+24(SP), SI				// Start of round keys.
		LEAQ	·LSEncLookup(SB), DX		// Cipher matrix base address.
		MOVQ	DX, CX						// Save value of DX.
		XORQ	DI, DI						// Loop counter.
		MOVQ	$0x1000, R11				// Constant for offset increment.

L1:		NOP
		MOVOU	(SI), X1					// Load round key.
		PXOR	X1, X0						// XOR with current round key.

		PEXTRB	$0, X0, AX					// Extract reference byte.
		SHLQ	$4, AX						// Element is 16 bytes long.
		ADDQ	DX, AX						// Add offset to base.
		MOVOU	(AX), X2					// Read element.
											// No XOR here, just loading.
		
		ADDQ	R11, DX						// Row is 4096 bytes long.
		PEXTRB	$1, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2						// XOR with next element.
											// Repeat same construction
											// for each byte in block.
		ADDQ	R11, DX					
		PEXTRB	$2, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$3, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$4, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$5, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$6, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$7, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$8, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$9, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$10, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$11, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$12, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$13, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$14, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$15, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	$16, SI						// Next round key.
		MOVOU	X2, X0						// Move result to PT.
		MOVQ	CX, DX
		
		ADDQ	$1,	DI						// Counter.
		CMPQ    DI, $9						// Repeat loop (nine rounds).
		JLT		L1
		
		MOVOU	(SI), X1					// Get last key.
		PXOR	X1, X0						// XOR it.
		

		MOVOU	X0, ret+184(SP)				// Done. Move result to stack.
			
		RET									// Return.

TEXT ·DoEncryptCounter(SB), $0-192
// Counter mode
// Almost the same as DoEncrypt, the only difference is nonce processing
// (register X0) and XOR of plan text block at the end.

		MOVOU	nonce+8(SP), X0
		MOVOU	pt+24(SP), X5
		
		LEAQ	rk+40(SP), SI
		LEAQ	·LSEncLookup(SB), DX
		MOVQ	DX, CX
		XORQ	DI, DI
		MOVQ	$0x1000, R11

L2:		NOP
		MOVOU	(SI), X1
		PXOR	X1, X0

		PEXTRB	$0, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X2
						
		
		ADDQ	R11, DX
		PEXTRB	$1, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
						
						
		ADDQ	R11, DX					
		PEXTRB	$2, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$3, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$4, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$5, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$6, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$7, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$8, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$9, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$10, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$11, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$12, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$13, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$14, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$15, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	$16, SI
		MOVOU	X2, X0
		MOVQ	CX, DX
		
		ADDQ	$1,	DI
		CMPQ    DI, $9
		JLT		L2
		
		MOVOU	(SI), X1
		PXOR	X1, X0
		
		PXOR	X0, X5						// XOR with PT block.
		MOVOU	X5, ret+200(SP)
			
		RET



TEXT ·DoDecrypt(SB), $0-176
// Decryption. Significantly less optimized, than
// DoEncrypt().

		MOVOU	ct+8(SP), X0				// CT (CipherText), source.
		LEAQ	rk+168(SP), SI				// Point to the last of keys.
		
		MOVQ	$0x1000, R11				// Constant for offset increment.
		LEAQ	·LInvLookup(SB), DX
		
		PEXTRB	$0, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X2
				
		ADDQ	R11, DX						// Row is 4096 bytes long.
		PEXTRB	$1, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2						// XOR with next element.
											
		ADDQ	R11, DX					
		PEXTRB	$2, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$3, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$4, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$5, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$6, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$7, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$8, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$9, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$10, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$11, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$12, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$13, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$14, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$15, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		MOVOU	X2, X0
	
		LEAQ	·SLDecLookup(SB), DX
		MOVQ	DX, CX						// Save value of DX.
		XORQ	DI, DI						// Loop counter.

L3:		NOP
		MOVOU	(SI), X1					// Load round key.
		PXOR	X1, X0						// XOR with current round key.

		PEXTRB	$0, X0, AX					// Extract reference byte.
		SHLQ	$4, AX						// Element is 16 bytes long.
		ADDQ	DX, AX						// Add offset to base.
		MOVOU	(AX), X2					// Read element.
											// No XOR here, just loading.
		
		ADDQ	R11, DX						// Row is 4096 bytes long.
		PEXTRB	$1, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2						// XOR with next element.
											// Repeat same construction
											// for each byte in block.
		ADDQ	R11, DX					
		PEXTRB	$2, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$3, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$4, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$5, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$6, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$7, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$8, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$9, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$10, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$11, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$12, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$13, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
	
		ADDQ	R11, DX
		PEXTRB	$14, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		ADDQ	R11, DX
		PEXTRB	$15, X0, AX
		SHLQ	$4, AX
		ADDQ	DX, AX
		MOVOU	(AX), X3
		PXOR	X3, X2
		
		SUBQ	$16, SI						// Next round key.
											// In reverse order.
		MOVOU	X2, X0						// Move result to PT.
		MOVQ	CX, DX
		
		ADDQ	$1,	DI						// Counter.
		CMPQ    DI, $8						// Repeat loop (eight rounds).
		JLT		L3
		
		MOVOU	(SI), X1					
		PXOR	X1, X0						
		SUBQ	$16, SI
		LEAQ	·PiInverseTable(SB), DX	// Get inversed Pi table address.
		
		PEXTRB	$0, X0, AX
		ADDQ	DX, AX
		MOVB	(AX), BX
		PINSRB	$0, BX, X2
			
		PEXTRB	$1, X0, AX
		ADDQ	DX, AX
		MOVB	(AX), BX
		PINSRB	$1, BX, X2
		
		PEXTRB	$2, X0, AX
		ADDQ	DX, AX
		MOVB	(AX), BX
		PINSRB	$2, BX, X2
		
		PEXTRB	$3, X0, AX
		ADDQ	DX, AX
		MOVB	(AX), BX
		PINSRB	$3, BX, X2
		
		PEXTRB	$4, X0, AX
		ADDQ	DX, AX
		MOVB	(AX), BX
		PINSRB	$4, BX, X2
				
		PEXTRB	$5, X0, AX
		ADDQ	DX, AX
		MOVB	(AX), BX
		PINSRB	$5, BX, X2

		PEXTRB	$6, X0, AX
		ADDQ	DX, AX
		MOVB	(AX), BX
		PINSRB	$6, BX, X2

		PEXTRB	$7, X0, AX
		ADDQ	DX, AX
		MOVB	(AX), BX
		PINSRB	$7, BX, X2
		
		PEXTRB	$8, X0, AX
		ADDQ	DX, AX
		MOVB	(AX), BX
		PINSRB	$8, BX, X2
		
		PEXTRB	$9, X0, AX
		ADDQ	DX, AX
		MOVB	(AX), BX
		PINSRB	$9, BX, X2
		
		PEXTRB	$10, X0, AX
		ADDQ	DX, AX
		MOVB	(AX), BX
		PINSRB	$10, BX, X2
		
		PEXTRB	$11, X0, AX
		ADDQ	DX, AX
		MOVB	(AX), BX
		PINSRB	$11, BX, X2
		
		PEXTRB	$12, X0, AX
		ADDQ	DX, AX
		MOVB	(AX), BX
		PINSRB	$12, BX, X2
		
		PEXTRB	$13, X0, AX
		ADDQ	DX, AX
		MOVB	(AX), BX
		PINSRB	$13, BX, X2
		
		PEXTRB	$14, X0, AX
		ADDQ	DX, AX
		MOVB	(AX), BX
		PINSRB	$14, BX, X2
		
		PEXTRB	$15, X0, AX
		ADDQ	DX, AX
		MOVB	(AX), BX
		PINSRB	$15, BX, X2
		
		MOVOU	(SI), X1					
		PXOR	X1, X2
		
		MOVOU	X2, ret+184(SP)				// Done. Move result to stack.
			
		RET			
