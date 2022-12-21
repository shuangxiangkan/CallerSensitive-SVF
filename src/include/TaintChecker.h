//===- LeakChecker.h -- Detecting memory leaks--------------------------------//
//
//                     SVF: Static Value-Flow Analysis
//
// Copyright (C) <2013->  <Yulei Sui>
//

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
//===----------------------------------------------------------------------===//

/*
 * LeakChecker.h
 *
 *  Created on: Dec 10, 2022
 *      Author: Shuangxiang Kan
 */

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
