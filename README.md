# ExtractImportFunctionAndMatchLibrary
    就是用来提取二进制里import表中所有的函数，去和so库匹配的脚本
# ghidra脚本
ImportTableExtractor.py 在ghidra环境中运行获得import函数表，示例是import_table.txt
# python脚本
MatchFunctionsLibs.py匹配函数与so库，生成匹配和不匹配的txt
# 问题：
1.ghidra中有的函数没有函数名，没有放在import库中
2.原本是想提取出所有函数去找开源项目，但是行不通