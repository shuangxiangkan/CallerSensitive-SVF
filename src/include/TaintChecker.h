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
    typedef FIFOWorkList<const CallICFGNode*> CSWorkList;
    typedef ProgSlice::VFWorkList WorkList;
    typedef NodeBS SVFGNodeBS;

    /// Constructor
    TaintChecker()
    {
    }
    /// Destructor
    virtual ~TaintChecker()
    {
    }

    /// We start from here
    virtual bool runOnModule(SVFIR* pag, std::vector<JsonReaderWriter::nativeCallee> nativeCallees)
    {
        /// start analysis
        callees = nativeCallees;
        analyze(pag->getModule());
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
        return SaberCheckerAPI::getCheckerAPI()->isMemDealloc(fun);
    }
    //@}

protected:
    /// Report leaks
    //@{
    virtual void reportBug(ProgSlice* slice) override;
    void reportTaint(const SVFGNode* src);
    void reportPartialTaint(const SVFGNode* src);
    //@}

    inline void addSrcToParaPos(const SVFGNode* src, u32_t pos)
    {
        srcToParaPosMap[src] = pos;
    }
    inline const u32_t getSrcParmPos(const SVFGNode* src)
    {
        SVFGNodeToParaPosMap::iterator it =srcToParaPosMap.find(src);
        assert(it!=srcToParaPosMap.end() && "source node not a parameter??");
        return it->second;
    }

    JsonReaderWriter::nativeCallee getNativeCallee();

    //@}
private:
    SVFGNodeToCSIDMap srcToCSIDMap;
    SVFGNodeToParaPosMap srcToParaPosMap;
    std::vector<JsonReaderWriter::nativeCallee> callees;
};

} // End namespace SVF

#endif /* LEAKCHECKER_H_ */
