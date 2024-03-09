# ExtractImportFunctionAndMatchLibrary
    就是用来提取二进制里import表中所有的函数，去和so库匹配的脚本
# 1. ghidra脚本
AllFunctionNameExtractor.py 在ghidra环境中运行获得所有函数函数名，示例是all_function_name.txt
# 2. python脚本1
MatchFunctionsLibs.py匹配函数与so库，生成匹配和不匹配的txt
# 3. python脚本2
GetPossibleProject.py调用SourceGraph的api去匹配开源项目，结果如projects.txt
# 问题：
缺少符号表的情况下ghidra中有的函数没有函数名
