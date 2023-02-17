#include "Util/Options.h"
#include "TaintChecker.h"
#include "SVF-LLVM/BasicTypes.h"

using namespace SVF;
using namespace SVFUtil;


/*!
 * Initialize sources
 */
void TaintChecker::initSrcs()
{
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
                const PAGNode *fun_arg = *funArgIt;
                if (currentNativeCallee.taintedArgs.size() == 0)
                {
                    if (fun_arg->isPointer() && index >= 2)
                    {
                        const SVFGNode* node = svfg->getFormalParmVFGNode(fun_arg);
                        // std::cout << node->getValue()->getType()->toString() << std::endl;
                        addToSources(node);
                        addSrcToParaPos(node, index-2);
                        
                        std::string paraType = node->getValue()->getType()->toString();
                        if (paramTypeToPosMap.find(paraType) != paramTypeToPosMap.end())
                        {
                            paramTypeToPosMap[paraType].push_back(index - 2);
                        }
                        else
                        {
                            std::vector<int> pos;
                            pos.push_back(index - 2);
                            paramTypeToPosMap[paraType] = pos;
                        }

                        
                    }
                }
                else if (fun_arg->isPointer() && std::find(currentNativeCallee.taintedArgs.begin(), currentNativeCallee.taintedArgs.end(), index - 2) != currentNativeCallee.taintedArgs.end())
                {
                    const SVFGNode* node = svfg->getFormalParmVFGNode(fun_arg);
                    // std::cout << node->getValue()->getType()->toString() << std::endl;
                    addToSources(node);
                    addSrcToParaPos(node, index-2);
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
    SVFIR* pag = getPAG();
    // Function return value as sinks
    const SVFModule::FunctionSetType& functions = pag->getModule()->getFunctionSet();
    for (SVFModule::FunctionSetType::const_iterator func_iter = functions.begin(); func_iter != functions.end(); func_iter++)
    {
        const SVFFunction*  fun = *func_iter;
        if (strstr(fun->getName().c_str(), currentNativeCallee.nativeMethodName.c_str()))
        {
            if (pag->funHasRet(fun) && pag->getFunRet(fun)->isPointer())
            {
                const SVFGNode *snk = svfg->getFormalRetVFGNode(pag->getFunRet(fun));
                addToSinks(snk);
                addFunToSink(snk, "RetValue");
            }
        }
    }
    // library functions as sinks
    for(SVFIR::CSToArgsListMap::iterator it = pag->getCallSiteArgsMap().begin(),
            eit = pag->getCallSiteArgsMap().end(); it!=eit; ++it)
    {
        PTACallGraph::FunctionSet callees;
        getCallgraph()->getCallees(it->first,callees);
        for(PTACallGraph::FunctionSet::const_iterator cit = callees.begin(), ecit = callees.end(); cit!=ecit; cit++)
        {
            const SVFFunction* fun = *cit;
            if (isSinkLikeFun(fun))
            {
                SVFIR::SVFVarList &arglist = it->second;
                assert(!arglist.empty()	&& "no actual parameter at deallocation site?");
                /// we only choose pointer parameters among all the actual parameters
                for (SVFIR::SVFVarList::const_iterator ait = arglist.begin(),
                        aeit = arglist.end(); ait != aeit; ++ait)
                {
                    const PAGNode *pagNode = *ait;
                    if (pagNode->isPointer())
                    {
                        const SVFGNode *snk = getSVFG()->getActualParmVFGNode(pagNode, it->first);
                        addToSinks(snk);
                        addFunToSink(snk, fun->getName());

                        // For any multi-level pointer e.g., XFree(void** pagNode) that passed into a ExtAPI::EFT_FREE_MULTILEVEL function (e.g., XFree),
                        // we will add the DstNode of a load edge, i.e., dummy = *pagNode
                        SVFStmt::SVFStmtSetTy& loads = const_cast<PAGNode*>(pagNode)->getOutgoingEdges(SVFStmt::Load);
                        for(const SVFStmt* ld : loads)
                        {
                            if(SVFUtil::isa<DummyValVar>(ld->getDstNode()))
                                addToSinks(getSVFG()->getStmtVFGNode(ld));
                        }
                    }
                }
            }
        }
    }
}

void TaintChecker::reportTaint2(const SVFGNode* src, const SVFGNodeSet& sinks)
{
    for (SVFGNodeSet::const_iterator it = sinks.begin(), eit = sinks.end();
            it!=eit; ++it)
    {
        const SVFGNode* node = *it;
        std::string sinkName = getSinkFunName(node);
        ParamTypeToPos::iterator it1;
        for (it1 = paramTypeToPosMap.begin(); it1 != paramTypeToPosMap.end(); ++it1)
        {
            std::vector<int> pos = it1->second;
            for(std::vector<int>::iterator it2 = pos.begin(); it2 != pos.end(); ++it2)
            {
                if (sinkName == "RetValue")
                {
                    JsonReaderWriter::getJsonReaderWriter()->writeResultToYaml(*it2, currentNativeCallee);
                }
                else
                {
                    SVFUtil::errs() << bugMsg2("TaintLeak at: ");
                    std::cout << sinkName << "()" << " pos: " << *it2 << std::endl;
                }      
            }
        }  
    }
}

void TaintChecker::reportTaint(const SVFGNode* src, const SVFGNodeSet& sinks)
{
    for (SVFGNodeSet::const_iterator it = sinks.begin(), eit = sinks.end();
            it!=eit; ++it)
    {
        const SVFGNode* node = *it;
        std::string sinkName = getSinkFunName(node);
        const u32_t pos = getSrcParmPos(src);
        if (sinkName == "RetValue")
        {
            JsonReaderWriter::getJsonReaderWriter()->writeResultToYaml(pos, currentNativeCallee);
        }
        else
        {
            SVFUtil::errs() << bugMsg2("TaintLeak at: ");
            std::cout << sinkName << "()" << std::endl;
        }      
    }
}

void TaintChecker::reportBug(ProgSlice* slice)
{
    if(isAllPathReachable() == true)
    {
        reportTaint2(slice->getSource(), slice->getSinks());
    }else if(isSomePathReachable() == true)
    {
        reportTaint2(slice->getSource(), slice->getSinks());
    }
}

void TaintChecker::getNativeCallees(std::string jsonPath)
{
    nativeCalleesVec = JsonReaderWriter::getJsonReaderWriter()->getCallees(jsonPath);
}