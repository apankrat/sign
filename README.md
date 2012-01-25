    =============================================================================
    
    	sign 1.0.7
    
    ===
    
    	Public-key cryptography based file signing and signature
    	verfication utility.
    
    	http://swapped.cc/sign
    
    ===
    
    	Distributed under terms of BSD license. 
    
    ===
    
    	To build with GNU tools run
    		gmake
    
    	To install in /usr 
    		gmake install
    
    	To clean up the build files
    		gmake clean
    	
    	To generate signing key
    		sign -g
    
    	To sign the file
    		sign <filename> --title <title>
    
    	To verify and strip the signature
    		unsign <filename>
    
    	To test the signature
    		unsign -t <filename>
    
    ===
    
    	1.0.7 - Aug 07, 2004
    		* fixed 'test' (-t) mode (kudos to Kai for noticing)
    		
    	1.0.6 - Aug 03, 2004
    		* fixed a bug in error message formatting when the original
    		  file extension cannot be guessed (--verify mode)
    		* fixed a bug in key fingerprint formatting routine
    		
    	1.0.5 - May 28, 2004
    		* added missing buffer range check in buf_parse_bignum()
    
    	1.0.4 - May 14, 2004
    		* reworked code a bit to make it build cleanly on OpenBSD
    		  (thanks to Jason Ish for BSD shell); 
    		* fixed another typo in man page (thanks to Ross Richardson)
    		
    		
    	1.0.3 - May 5, 2004
    		* fixed man page typos (thanks to Ross Richardson)
    	
    	1.0.2 - May 3, 2004
    		* an initial public release
    
    =============================================================================
    Copyright (c) 2004-2011, Alex Pankratov (ap@swapped.cc). All rights reserved.
    
