#ifndef JSONREADERWRITER_H_
#define JSONREADERWRITER_H_

#include "Util/cJSON.h"
#include <string>
#include <vector>


namespace SVF
{
class JsonReaderWriter
{

public:

    class nativeCallee
    {
    public:
        std::string nativeMethodName;
        std::string retType;
        std::vector<std::string> argsType;
        std::vector<int> taintedArgs;
    };

    static JsonReaderWriter *jrw;

    static JsonReaderWriter *getJsonReaderWriter();

    static void destroy();

    // Get .json file path from input
    void getJsonAndYmlFilePath(int &argc, char **argv);

    // Get specifications of caller functions
    cJSON *parseCallerJson(std::string path);

    std::vector<nativeCallee> getCallees(std::string jsonPath);

    void writeResultToYaml(u32_t pos, nativeCallee callee);

    bool isTransferKeyWord();
    
    std::string jsonPath;
    
    std::string ymlPath;
 
};

} // End namespace SVF

#endif /* JSONREADERWRITER_H_ */