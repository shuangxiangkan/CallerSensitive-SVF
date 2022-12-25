
#include "SVF-LLVM/LLVMUtil.h"
#include "SVF-LLVM/SVFIRBuilder.h"
#include "TaintChecker.h"
#include "JsonReaderWriter.h"
#include "SABER/LeakChecker.h"
#include "SABER/FileChecker.h"
#include "SABER/DoubleFreeChecker.h"
#include "Util/CommandLine.h"
#include "Util/Options.h"
#include "Util/Z3Expr.h"


using namespace llvm;
using namespace SVF;


static Option<bool> TAINTCHECKER(
    "taint",
    "Taint Detection",
    false
);


int main(int argc, char ** argv)
{
    JsonReaderWriter::getJsonReaderWriter()->getJsonAndYmlFilePath(argc, argv);

    char **arg_value = new char*[argc];
    std::vector<std::string> moduleNameVec;
    moduleNameVec = OptionBase::parseOptions(
                        argc, argv, "Source-Sink Bug Detector", "[options] <input-bitcode...>"
                    );

    if (Options::WriteAnder() == "ir_annotator")
    {
        LLVMModuleSet::getLLVMModuleSet()->preProcessBCs(moduleNameVec);
    }

    SVFModule* svfModule = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(moduleNameVec);
    SVFIRBuilder builder(svfModule);
    SVFIR* pag = builder.build();
    
    std::unique_ptr<TaintChecker> taint;

    taint = std::make_unique<TaintChecker>();

    taint->runOnModule(pag);

    delete[] arg_value;
    JsonReaderWriter::destroy();

    return 0;

}