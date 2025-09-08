#!/bin/bash

start=$(date +%s)
function BASIC_CHECK()
{	
	#1.1 Check the current user; exit if not ‘root’.

	if [ "$(id -u )" = "0" ];then
		echo -e "\e[31mGreat! You are root\e[0m"
	else
		echo "Bye, Start again the script, but login as root"
		exit
	fi
	
	#1.2 Allow the user to specify the filename; check if the file exists.
 			
	while true;do
		read -p "What is the file name which you want to analyze? -> " file
		rm -rf analysis
		mkdir analysis
		cp $file analysis
		sleep 3
		cd analysis
		if [ -f "$file" ];then
			echo -e "\e[31mFile exists\e[0m"
			break
		else
			echo -e "\e[31mFile does not exist.Try again\e[0m"
		fi	
	done
	#1.3 Create a function to install the forensics tools if missing.
	for app in bulk_extractor binwalk foremost strings vol.py;do
		APP_PATH=$(which $app 2> /dev/null)
		if [ "$app" = "bulk_extractor" ];then
			if [ -z "$APP_PATH" ]; then
				echo -e "\e[31mInstalling bulk_extractor...\e[0m"
				sudo apt install bulk-extractor -y
			else	
				echo -e "\e[32mbulk_extractor is installed\e[0m"	
			fi
		fi
		
		if [ "app" = "binwalk" ]; then
			if [ -z "$APP_PATH" ]; then
				echo -e "\e[31mInstalling binwalk...\e[0m"
				sudo apt install binwalk -y
			else
				echo "\e[32mbinwalk is installed\e[0m"
			fi
		fi

		if [ "$app" = "foremost" ]; then
			if [ -z "$APP_PATH" ]; then
				echo -e "\e[31mInstalling foremost\e[0m"
				sudo apt install foremost -y
			else
				echo -e "\e[32mforemost is installed\e[0m"
			fi
		fi
	
		if [ "$app" = "strings" ]; then
			if [ -z "$APP_PATH" ]; then
				echo -e "\e[31mInstalling strings\e[0m"
				sudo apt install binutils -y
			else
				echo -e "\e[32mstrings is installed\e[0m"
			fi
		fi
	
		if [ "$app" = "vol.py" ]; then
			if [ -z "$APP_PATH" ]; then
				echo -e "\e[31mInstalling volatility\e[0m"
				sudo apt update
				sudo apt install -y python2 python2.7-dev build-essential git curl
				curl -sS https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
				sudo python2 get-pip.py
				sudo python2 -m pip install -U 'pip<21' 'setuptools<45' wheel
				sudo python2 -m pip install -U pycryptodome distorm3 yara-python==3.11.0
				sudo python2 -m pip install -U git+https://github.com/volatilityfoundation/volatility.git
			else
				echo -e "\e[32mvolatility is installed\e[0m"
			fi
		fi
	done	
}

sleep 2
#1.4 Use different carvers to automatically extract data.
#1.5 Data should be saved into a directory.
function CARVING() {
	rm -rf extracted_bulk
	echo -e "\e[31mThe extracted info with bulk_extractor will be here in the directory: extracted_bulk\e[0m"
	bulk_extractor -o extracted_bulk $file 
	
	echo -e "\e[31mThe extracted info with foremost will be here in the directory: extracted_foremost\e[0m"
	foremost -i $file -o extracted_foremost 
}


#1.6 Attempt to extract network traffic; if found, display to the user the location and size.
function NETWORK_TRAFFIC(){
	file_search=$(find extracted_bulk -type f -name "*.pcap")
	if [ -z "$file_search" ];then
		echo "Network file is not founded" 
	else
		echo -e "\e[31mLocation of the network file is here: $file_search\e[0m" 
		echo -e "\e[31mIt's size is:$(ls -lh $file_search | awk '{print $5}')\e[0m"	
	fi
}

#1.7 Check for human-readable (exe files, passwords, usernames, etc.).
function SEARCH(){
	while true;do
		echo "What are you searching?"
		echo -e "\e[31mChoose an option\e[0m"
		echo -e "\e[33m1)Passwords\e[0m"
		echo -e "\e[33m2)Usernames\e[0m"
		echo -e "\e[33m3)Hash\e[0m"
		echo -e "\e[33m4)Something custom\e[0m"
		echo -e "\e[33m5)Exit\e[0m"

		read -p "Enter a choice [1-5]: " choice
		
		case $choice in
			1)
				strings $file | grep -i passwords > strings_passwords
				echo -e "\e[32mThe extracted info by searching for passwords is in file: strings_passwords\e[0m"
			;;
			2)
				strings $file | grep -iE "username|usernames" > strings_usernames
                                echo -e "\e[32mCheck the extracted info by searching for usernames in file: strings_usernames\e[0m"
			;;
			3)
				strings $file | grep -i hash > strings_hash
                                echo -e "\e[32mCheck the extracted info by searching for hash in file: strings_hash\e[0m"
			;;
			4)
				read -p "What custom are you searching? " answer
				strings $file | grep -i $answer > strings_$answer
				echo -e "\e[32mCheck the extracted info by search for $answer in file: strings_$answer\e[0m"
			;;
			5)
				echo -e "\e[32mExit\e[0m"
				break
			;;
			*)
				echo -e "\e[32mInvalid choice, try again\e[0m"
			;;
		esac
	done
}

function VOLATILITY_CHECK()
{
	#2.1 Check if the file can be analyzed in Volatility; if yes, run Volatility.
	check=$(vol.py -f $file imageinfo | grep  -io "No suggestion")
	if [ "$check" = "No suggestion" ];then
		echo -e "\e[31mThere is no suggested profiles.\e[0m"
		echo -e "\e[31mTry with another file, volatility check failed.\e[0m"
	else
		#2.2 Find the memory profile and save it into a variable.
		echo -e "\e[31mThis file can be analyzed with volatility\e[0m"
		profile=$(vol.py -f memdump.mem imageinfo | grep -i "Suggested Profile" | awk '{print $5}')
		echo -e "\e[1;31mThis is the profile of your file:$profile\e[0m"
		
		 #2.3 Display the running processes.     
		for command in pslist pstree;do
			sleep 2
			if [ $command = "pslist" ];then
				echo -e "\e[1;31mList of the processes of a system\e[0m"
					vol.py -f $file --profile=$profile $command
			
			else
				echo -e "\e[1;31mView the process listing as a tree form. Child process are indicated using indention and periods\e[0m"
					vol.py -f $file --profile=$profile $command 
			fi
		done
		#2.4 Display network connections.
		echo -e "\e[1;31mChecking for TCP connections that were active at the time of the memory acquisition\e[0m"
		vol.py -f $file --profile=$profile connections
		echo -e "\e[1;31mChecking for artifacts from previous connections that have since been terminated, in addition to the active ones\e[0m"
		vol.py -f $file --profile=$profile connscan

		#2.5 Attempt to extract registry information.		
		echo -e "\e[1;31mChecking for registry info before dump\e[0m"
		registry=$(vol.py -f $file --profile=$profile hivelist | grep -io "No suitable address space mapping found")
		if [ "$registry" = "No suitable address space mapping found" ]; then
			echo -e "\e[1;31mNo registry info was found\e[0m"
		else	
			echo -e "\e[1;31mGetting the registry info...\e[0m"
			rm -rf registry_info
			mkdir registry_info
			vol.py -f $file --profile=$profile dumpregistry -D registry_info
		fi

	fi
	
}

function RESULTS(){
	echo -e "\e[1;32mGeneral statistics\e[0m "
	#Getting epoch time
	end=$(date +%s)
	
	final=$(( end - start ))
	minutes=$(( final / 60 ))
	seconds=$(( final % 60 ))
	#Finding all files in all subdirectories
	found_files=$(find ./*/ -type f | wc -l)
	
	echo -e "\e[31mTime of the analys: $minutes minutes and $seconds seconds.\e[0m"
	echo -e "\e[31mFound files: $found_files\e[0m"
	echo "Top 5 largest files found are:"
	find . -type f -exec du -h {} \; | sort -hr | head -n 5
	
 	#If there is no such a file, the error will not be printed in the terminal
	rm report.txt 2> /dev/null
	touch report.txt
	echo "=================================" >> report.txt
	echo " 	General Report         " >> report.txt
	echo "=================================" >> report.txt
	echo >> report.txt
	echo "This report is generate at: $(date)" >> report.txt
	echo  >> report.txt
	echo "Time of the analys: $minutes minutes and $seconds seconds." >> report.txt
	echo  >> report.txt
	echo "Found files: $found_files" >> report.txt
	echo >> report.txt
	echo "Top 5 largest files: " >> report.txt
	find . -type f -exec du -h {} \; | sort -hr | head -n 5  >> report.txt
	echo >> report.txt
	echo "User who ran the script:" >> report.txt
	whoami >> report.txt
	echo >> report.txt
	echo "System details on which the script was running: " >> report.txt
	uname -a >> report.txt
	echo  >> report.txt
	echo "Hash SHA1 of the file which was scanned:" >> report.txt
	#sha1sum $file >> report.txt
	echo -e "\e[31mThe report is created: report.txt\e[0m"
}

function ZIP_FILES(){
	read -p "Do you want zip file to have password? y/n " pass_ans
	read -p "What will be the name of your zip file? " name
	if [ "$pass_ans" = "y" ];then
		zip -r -e "$name.zip" report.txt registry_info extracted_foremost extracted_bulk $(ls strings_* 2>/dev/null || true)
	else
		zip -r "$name.zip" report.txt registry_info extracted_foremost extracted_bulk $(ls strings_* 2>/dev/null || true)	
	fi
	
	
}

function HIDDEN_FILES(){
	read -p "Do you want to analyze specific file, if it has any hidden files in it? y/n -> " answer
	if [ "$answer" = "y" ];then
		read -p "What is the name of the file? -> " file	
		binwalk $file
		read -p "Do you find any hidden file y/n ->" answer
		if [ "$answer" = "y" ];then
			read -p "What is the decimal number of the file you wanna extract? " number
			echo -e "\e[31mExtracting....."
			dd if=$file of=extracted_result bs=1 skip=$number
			echo -e "\e[32mName of the file is: extracted_results and it's location is in: $(pwd)\e[0m"
		else
			echo "Exit"
			exit
		fi
	else
		echo "Exit"
		exit
	fi
}

BASIC_CHECK
CARVING
NETWORK_TRAFFIC
SEARCH
VOLATILITY_CHECK
RESULTS
ZIP_FILES
HIDDEN_FILES
