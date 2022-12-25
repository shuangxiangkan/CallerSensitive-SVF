#include "Util/Options.h"
#include "TaintChecker.h"

using namespace SVF;
using namespace SVFUtil;


/*!
 * Initialize sources
 */
void TaintChecker::initSrcs()
{
    clearSources();
    SVFIR* pag = getPAG();
    if (nativeCalleesVec.size() <= 0)
        assert(false && "No native method for taint to analyze");
    currentNativeCallee = nativeCalleesVec.back();
    nativeCalleesVec.pop_back();
    const SVFModule::FunctionSetType& functions = pag->getModule()->getFunctionSet();
    // function parameters are used as sources
    for (SVFModule::FunctionSetType::const_iterator func_iter = functions.begin(); func_iter != functions.end(); func_iter++)
    {
        const SVFFunction*  fun = *func_iter;
        
        if (strstr(fun->getName().c_str(), currentNativeCallee.nativeMethodName.c_str()))
        {
            const SVFIR::SVFVarList& funArgList = pag->getFunArgsList(fun);
            u32_t index = 0;
            for (SVFIR::SVFVarList::const_iterator funArgIt = funArgList.begin(); funArgIt != funArgList.end(); funArgIt++)
            {
                // Use the parameters provided by .json as sources
                if (index > 1 && std::find(currentNativeCallee.taintedArgs.begin(), currentNativeCallee.taintedArgs.end(), index - 2) != currentNativeCallee.taintedArgs.end())
                {
                    const PAGNode *fun_arg = *funArgIt;
                    const SVFGNode* node = svfg->getFormalParmVFGNode(fun_arg);
                    addToSources(node);
                    addSrcToParaPos(node, index - 2);
                }
                index++;
            }
            break;
        }
    }
}

// At present, only the function return value is used as sinks. In the future, some functions will be added as sinks, 
// such as functions for reading and writing files
void TaintChecker::initSnks()
{
    clearSinks();
    SVFIR* pag = getPAG();
    const SVFModule::FunctionSetType& functions = pag->getModule()->getFunctionSet();
    for (SVFModule::FunctionSetType::const_iterator func_iter = functions.begin(); func_iter != functions.end(); func_iter++)
    {
        const SVFFunction*  fun = *func_iter;
        if (strstr(fun->getName().c_str(), currentNativeCallee.nativeMethodName.c_str()))
        {
            const PAGNode* fun_return = pag->getFunRet(fun);
            const SVFGNode *snk = svfg->getFormalRetVFGNode(fun_return);
            addToSinks(snk);
        }
    }
}


void TaintChecker::reportTaint(const SVFGNode* src)
{
    const u32_t pos = getSrcParmPos(src);
    JsonReaderWriter::getJsonReaderWriter()->writeResultToYaml(pos, currentNativeCallee);
}

void TaintChecker::reportPartialTaint(const SVFGNode* src)
{
    const u32_t pos = getSrcParmPos(src);
    JsonReaderWriter::getJsonReaderWriter()->writeResultToYaml(pos, currentNativeCallee);
}

void TaintChecker::reportBug(ProgSlice* slice)
{
    if(isAllPathReachable() == true || isSomePathReachable() == true)
    {
        reportTaint(slice->getSource());
    }
}

void TaintChecker::getNativeCallees(std::string jsonPath)
{
    nativeCalleesVec = JsonReaderWriter::getJsonReaderWriter()->getCallees(jsonPath);
}