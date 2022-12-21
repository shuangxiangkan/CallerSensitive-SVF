#include "SVFIR/SVFType.h"
#include "SVF-LLVM/LLVMUtil.h"
#include "JsonReaderWriter.h"
#include <sys/stat.h>
#include <fstream>
#include <iostream>

using namespace SVF;

JsonReaderWriter *JsonReaderWriter::jrw = nullptr;

JsonReaderWriter *JsonReaderWriter::getJsonReaderWriter()
{
    if (jrw == nullptr)
    {
        jrw = new JsonReaderWriter();
    }
    return jrw;
}

void JsonReaderWriter::destroy()
{
    if (jrw!= nullptr)
    {
        delete jrw;
        jrw = nullptr;
    }
}


std::string JsonReaderWriter::getJsonFile(int &argc, char **argv)
{
    for (u32_t i = 0; i < argc; ++i)
    {
        std::string argument(argv[i]);
        // File is a .json file not a IR file
        if (strstr(argument.c_str(), ".json") && !LLVMUtil::isIRFile(argument))
        {
            for (int j = i; j < argc && j + 1 < argc; ++j)
                argv[j] = argv[j + 1];
            argc--;
            return argument;
        }
    }
    return nullptr;
}

cJSON *JsonReaderWriter::parseCallerJson(std::string path)
{
    FILE *file = NULL;
    std::string FILE_NAME = path;
    file = fopen(FILE_NAME.c_str(), "r");
    if (file == NULL)
    {
        assert(false && "Open Caller Json file fail!");
        return nullptr;
    }

    struct stat statbuf;
    stat(FILE_NAME.c_str(), &statbuf);
    u32_t fileSize = statbuf.st_size;

    char *jsonStr = (char *)malloc(sizeof(char) * fileSize + 1);
    memset(jsonStr, 0, fileSize + 1);

    u32_t size = fread(jsonStr, sizeof(char), fileSize, file);
    if (size == 0)
    {
        assert(false && "Read Caller Json file fails!");
        return nullptr;
    }
    fclose(file);

    // convert json string to json pointer variable
    cJSON *root = cJSON_Parse(jsonStr);
    if (!root)
    {
        free(jsonStr);
        return nullptr;
    }
    free(jsonStr);
    return root;
}

void JsonReaderWriter::getCallees(std::string jsonPath)
{
    cJSON *root = parseCallerJson(jsonPath);
    while (root)
    {
        JsonReaderWriter::nativeCallee callee;
        cJSON *item = root->child;
        while (item)
        {
            if (strstr(item->string, "nativeMethodName"))
            {
                callee.nativeMethodName = item->valuestring;
            }
            else if (strstr(item->string, "retType"))
            {
                callee.retType = item->valuestring;
            }
            else if (strstr(item->string, "argsType"))
            {
                cJSON *obj = item->child;
                while (obj)
                {
                    callee.argsType.push_back(obj->valuestring);
                    obj = obj->next;
                }
                
            }
            else if (strstr(item->string, "taintedArgsPos"))
            {
                cJSON *obj = item->child;
                while (obj)
                {
                    callee.taintedArgs.push_back(obj->valueint);
                    obj = obj->next;
                }         
            }
            item = item->next;
        }
        JsonReaderWriter::callees.push_back(callee);
        root = root->next;
    }
}

void JsonReaderWriter::writeResultToYaml(u32_t pos, nativeCallee callee)
{
    std::string start = " - { method: \"<";
    std::string calleeClass = "Main: ";
    std::string calleeRetType = callee.retType + " ";
    std::string calleeName = callee.nativeMethodName;
    std::string calleeArgs = "(";
    for(u32_t i = 0; i < callee.argsType.size() - 1; i++)
    {
        calleeArgs.append(callee.argsType[i]);
        calleeArgs.append(",");
    }
    calleeArgs.append(callee.argsType[callee.argsType.size() - 1]);
    calleeArgs.append(")>\", ");
    std::string from = "from: " + std::to_string(pos);
    std::string to = ", to: result, ";
    std::string taintType = "type: \"" + callee.argsType[pos] + "\" }";

    std::string result = start + calleeClass + calleeRetType + calleeName + calleeArgs + from + to + taintType;
    std::cout << result << std::endl;

    std::ofstream ofs;
    ofs.open("./nativeCalleeSummary.yml", std::ios::app);
    ofs << result << std::endl;
    ofs.close();



}


