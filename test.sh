#!/bin/bash
Green_Success(){
        echo '=================================================';

        printf '\033[1;32;40m[success]  %b\033[0m\n' "$1";

}

Yellow_Warnning(){
        echo '=================================================';

        printf '\033[1;33;40m[warnning]  %b\033[0m\n' "$1";

}

Red_Error(){
        echo '=================================================';

        printf '\033[1;31;40m[error]  %b\033[0m\n' "$1";

        exit 1;

}

Green_Success "成功"

Yellow_Warnning "警告"

Red_Error "错误"