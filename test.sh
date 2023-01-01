#!/bin/bash

result="Detected 0 taint flow(s):";
resultTxt=./result.txt;

 if [ ! -f $resultTxt ];then
    echo "result.txt does not exist";
    printf '\033[1;31;40m[fail]%b\033[0m\n';
    exit 1;

  else
    passresult=$(grep "$result" $resultTxt);
    if [ -n "$passresult" ];then
        echo "result is wrong";
        printf '\033[1;31;40m[fail]%b\033[0m\n';
        exit 1;
    # else
    #     printf '\033[1;32;40m[success]%b\033[0m\n';
    fi
 fi