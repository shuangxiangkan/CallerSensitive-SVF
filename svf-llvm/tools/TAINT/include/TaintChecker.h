#ifndef TAINTCHECKER_H_
#define TAINTCHECKER_H_

#include "SABER/SrcSnkDDA.h"
#include "SABER/SaberCheckerAPI.h"
#include "JsonReaderWriter.h"

namespace SVF
{

/*!
 * Static Taint Detector
 */
class TaintChecker : public SrcSnkDDA
{

public:
    typedef Map<const SVFGNode*,const CallICFGNode*> SVFGNodeToCSIDMap;
    typedef Map<const SVFGNode*,u32_t> SVFGNodeToParaPosMap;
    typedef Map<const SVFGNode*,std::string> SVFGNodeToFunMap;
    typedef FIFOWorkList<const CallICFGNode*> CSWorkList;
    typedef ProgSlice::VFWorkList WorkList;
    typedef NodeBS SVFGNodeBS;
    typedef std::vector<JsonReaderWriter::nativeCallee> NativeCalleeList;
    typedef JsonReaderWriter::nativeCallee NativeCallee;

    std::vector<std::string> sinkFuns = {
        // "_ZN7_JNIEnv17GetStringUTFCharsEP8_jstringPh",
        "__android_log_print",
        "extractFile",
        "_ZL13extractStreamP7JNIEnv_P13ISeekInStreamPKciP8_jobjectm",
        "OutFile_OpenUtf16",
        "Print",
        "suggestDomainCorrection",
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EPKcRKS3_"
    };


    /// Constructor
    TaintChecker()
    {
    }
    /// Destructor
    virtual ~TaintChecker()
    {
    }

    /// We start from here
    virtual bool runOnModule(SVFIR* pag)
    {
        /// start analysis
        getNativeCallees(JsonReaderWriter::getJsonReaderWriter()->jsonPath);
        while (nativeCalleesVec.size() > 0)
        {
            analyze(pag->getModule());
        }
        return false;
    }

    /// Initialize sources and sinks
    //@{
    /// Initialize sources and sinks
    virtual void initSrcs() override;
    virtual void initSnks() override;
    /// Whether the function is a heap allocator/reallocator (allocate memory)
    virtual inline bool isSourceLikeFun(const SVFFunction* fun) override
    {
        return SaberCheckerAPI::getCheckerAPI()->isMemAlloc(fun);
    }
    /// Whether the function is a heap deallocator (free/release memory)
    virtual inline bool isSinkLikeFun(const SVFFunction* fun) override
    {
        if (std::find(sinkFuns.begin(), sinkFuns.end(), fun->getName()) != sinkFuns.end())
        {
            return true;
        }
        return false;
    }
    //@}

protected:
    /// Report leaks
    //@{
    virtual void reportBug(ProgSlice* slice) override;
    void reportRetTaint(const SVFGNode* src);
    void reportFunTaint(const SVFGNodeSet& sinks);
    void reportTaint(const SVFGNode* src, const SVFGNodeSet& sinks);
    //@}

    inline void addSrcToParaPos(const SVFGNode* src, u32_t pos)
    {
        srcToParaPosMap[src] = pos;
    }
    inline void addFunToSink(const SVFGNode* src, std::string funName)
    {
        sinkToFun[src] = funName;
    }
    inline const u32_t getSrcParmPos(const SVFGNode* src)
    {
        SVFGNodeToParaPosMap::iterator it =srcToParaPosMap.find(src);
        assert(it!=srcToParaPosMap.end() && "source node not a parameter??");
        return it->second;
    }
    inline const std::string getSinkFunName(const SVFGNode* src)
    {
        SVFGNodeToFunMap::iterator it =sinkToFun.find(src);
        assert(it!=sinkToFun.end() && "sink node not a function??");
        return it->second;
    }
    void getNativeCallees(std::string jsonPath);

    //@}
private:
    SVFGNodeToCSIDMap srcToCSIDMap;
    SVFGNodeToParaPosMap srcToParaPosMap;
    SVFGNodeToFunMap sinkToFun;
    NativeCalleeList nativeCalleesVec;
    NativeCallee currentNativeCallee;
};

} // End namespace SVF

#endif /* LEAKCHECKER_H_ */