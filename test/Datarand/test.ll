; ModuleID = 'test.c'
source_filename = "test.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

%struct.Student = type { i32, [100 x i8] }
%struct.T = type { i32, void (i32)* }

@val1 = dso_local global i32 200, align 4, !dbg !0
@val2 = dso_local global i32 300, align 4, !dbg !6
@.str = private unnamed_addr constant [9 x i8] c"id = %d\0A\00", align 1
@.str.1 = private unnamed_addr constant [11 x i8] c"name = %s\0A\00", align 1
@.str.2 = private unnamed_addr constant [4 x i8] c"%d\0A\00", align 1
@.str.3 = private unnamed_addr constant [10 x i8] c"sensitive\00", section "llvm.metadata"
@.str.4 = private unnamed_addr constant [7 x i8] c"test.c\00", section "llvm.metadata"
@.str.5 = private unnamed_addr constant [6 x i8] c"%d %d\00", align 1

; Function Attrs: noinline nounwind uwtable
define dso_local void @printStudent(%struct.Student* %sptr) #0 !dbg !13 {
entry:
  %sptr.addr = alloca %struct.Student*, align 8
  store %struct.Student* %sptr, %struct.Student** %sptr.addr, align 8
  call void @llvm.dbg.declare(metadata %struct.Student** %sptr.addr, metadata !26, metadata !DIExpression()), !dbg !27
  %0 = load %struct.Student*, %struct.Student** %sptr.addr, align 8, !dbg !28
  %id = getelementptr inbounds %struct.Student, %struct.Student* %0, i32 0, i32 0, !dbg !29
  %1 = load i32, i32* %id, align 4, !dbg !29
  %call = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([9 x i8], [9 x i8]* @.str, i32 0, i32 0), i32 %1), !dbg !30
  %2 = load %struct.Student*, %struct.Student** %sptr.addr, align 8, !dbg !31
  %name = getelementptr inbounds %struct.Student, %struct.Student* %2, i32 0, i32 1, !dbg !32
  %arraydecay = getelementptr inbounds [100 x i8], [100 x i8]* %name, i32 0, i32 0, !dbg !31
  %call1 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([11 x i8], [11 x i8]* @.str.1, i32 0, i32 0), i8* %arraydecay), !dbg !33
  ret void, !dbg !34
}

; Function Attrs: nounwind readnone speculatable
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

declare dso_local i32 @printf(i8*, ...) #2

; Function Attrs: noinline nounwind uwtable
define dso_local void @func(i32 %a) #0 !dbg !35 {
entry:
  %a.addr = alloca i32, align 4
  %k = alloca i32, align 4
  %d = alloca i32, align 4
  %res = alloca i32, align 4
  store i32 %a, i32* %a.addr, align 4
  call void @llvm.dbg.declare(metadata i32* %a.addr, metadata !38, metadata !DIExpression()), !dbg !39
  call void @llvm.dbg.declare(metadata i32* %k, metadata !40, metadata !DIExpression()), !dbg !41
  store i32 10, i32* %k, align 4, !dbg !41
  call void @llvm.dbg.declare(metadata i32* %d, metadata !42, metadata !DIExpression()), !dbg !43
  store i32 100, i32* %d, align 4, !dbg !43
  call void @llvm.dbg.declare(metadata i32* %res, metadata !44, metadata !DIExpression()), !dbg !45
  %0 = load i32, i32* %a.addr, align 4, !dbg !46
  %1 = load i32, i32* %k, align 4, !dbg !47
  %add = add nsw i32 %0, %1, !dbg !48
  %2 = load i32, i32* %d, align 4, !dbg !49
  %add1 = add nsw i32 %add, %2, !dbg !50
  store i32 %add1, i32* %res, align 4, !dbg !45
  %3 = load i32, i32* %res, align 4, !dbg !51
  %call = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str.2, i32 0, i32 0), i32 %3), !dbg !52
  ret void, !dbg !53
}

; Function Attrs: noinline nounwind uwtable
define dso_local void @gunc(i32 %a) #0 !dbg !54 {
entry:
  %a.addr = alloca i32, align 4
  %k = alloca i32, align 4
  %d = alloca i32, align 4
  %res = alloca i32, align 4
  store i32 %a, i32* %a.addr, align 4
  call void @llvm.dbg.declare(metadata i32* %a.addr, metadata !55, metadata !DIExpression()), !dbg !56
  call void @llvm.dbg.declare(metadata i32* %k, metadata !57, metadata !DIExpression()), !dbg !58
  store i32 10, i32* %k, align 4, !dbg !58
  call void @llvm.dbg.declare(metadata i32* %d, metadata !59, metadata !DIExpression()), !dbg !60
  store i32 200, i32* %d, align 4, !dbg !60
  call void @llvm.dbg.declare(metadata i32* %res, metadata !61, metadata !DIExpression()), !dbg !62
  %0 = load i32, i32* %d, align 4, !dbg !63
  %1 = load i32, i32* %k, align 4, !dbg !64
  %sub = sub nsw i32 %0, %1, !dbg !65
  %2 = load i32, i32* %a.addr, align 4, !dbg !66
  %sub1 = sub nsw i32 %sub, %2, !dbg !67
  store i32 %sub1, i32* %res, align 4, !dbg !62
  %3 = load i32, i32* %res, align 4, !dbg !68
  %call = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str.2, i32 0, i32 0), i32 %3), !dbg !69
  ret void, !dbg !70
}

; Function Attrs: noinline nounwind uwtable
define dso_local void @dosomething(%struct.T* %tptr) #0 !dbg !71 {
entry:
  %tptr.addr = alloca %struct.T*, align 8
  store %struct.T* %tptr, %struct.T** %tptr.addr, align 8
  call void @llvm.dbg.declare(metadata %struct.T** %tptr.addr, metadata !81, metadata !DIExpression()), !dbg !82
  %0 = load %struct.T*, %struct.T** %tptr.addr, align 8, !dbg !83
  %funcptr = getelementptr inbounds %struct.T, %struct.T* %0, i32 0, i32 1, !dbg !84
  %1 = load void (i32)*, void (i32)** %funcptr, align 8, !dbg !84
  call void %1(i32 200), !dbg !85
  ret void, !dbg !86
}

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @main() #0 !dbg !87 {
entry:
  %retval = alloca i32, align 4
  %t = alloca %struct.T, align 8
  %stud = alloca %struct.Student, align 4
  %fptr = alloca void (i32)*, align 8
  %iptr = alloca i32*, align 8
  %k = alloca i32, align 4
  %j = alloca i32, align 4
  store i32 0, i32* %retval, align 4
  call void @llvm.dbg.declare(metadata %struct.T* %t, metadata !90, metadata !DIExpression()), !dbg !91
  %id = getelementptr inbounds %struct.T, %struct.T* %t, i32 0, i32 0, !dbg !92
  store i32 100, i32* %id, align 8, !dbg !93
  call void @llvm.dbg.declare(metadata %struct.Student* %stud, metadata !94, metadata !DIExpression()), !dbg !95
  call void @llvm.dbg.declare(metadata void (i32)** %fptr, metadata !96, metadata !DIExpression()), !dbg !97
  call void @llvm.dbg.declare(metadata i32** %iptr, metadata !98, metadata !DIExpression()), !dbg !100
  %iptr1 = bitcast i32** %iptr to i8*, !dbg !101
  call void @llvm.var.annotation(i8* %iptr1, i8* getelementptr inbounds ([10 x i8], [10 x i8]* @.str.3, i32 0, i32 0), i8* getelementptr inbounds ([7 x i8], [7 x i8]* @.str.4, i32 0, i32 0), i32 46), !dbg !101
  call void @llvm.dbg.declare(metadata i32* %k, metadata !102, metadata !DIExpression()), !dbg !103
  store i32 0, i32* %k, align 4, !dbg !103
  call void @llvm.dbg.declare(metadata i32* %j, metadata !104, metadata !DIExpression()), !dbg !105
  %0 = load i32, i32* %k, align 4, !dbg !106
  %add = add nsw i32 %0, 10, !dbg !107
  store i32 %add, i32* %j, align 4, !dbg !105
  call void @printStudent(%struct.Student* %stud), !dbg !108
  %1 = load i32, i32* %k, align 4, !dbg !109
  %2 = load i32, i32* %j, align 4, !dbg !110
  %call = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([6 x i8], [6 x i8]* @.str.5, i32 0, i32 0), i32 %1, i32 %2), !dbg !111
  %3 = load i32, i32* %j, align 4, !dbg !112
  %cmp = icmp slt i32 %3, 100, !dbg !114
  br i1 %cmp, label %if.then, label %if.else, !dbg !115

if.then:                                          ; preds = %entry
  store void (i32)* @func, void (i32)** %fptr, align 8, !dbg !116
  store i32* @val1, i32** %iptr, align 8, !dbg !118
  %funcptr = getelementptr inbounds %struct.T, %struct.T* %t, i32 0, i32 1, !dbg !119
  store void (i32)* @gunc, void (i32)** %funcptr, align 8, !dbg !120
  br label %if.end, !dbg !121

if.else:                                          ; preds = %entry
  store void (i32)* @gunc, void (i32)** %fptr, align 8, !dbg !122
  store i32* @val2, i32** %iptr, align 8, !dbg !124
  %funcptr2 = getelementptr inbounds %struct.T, %struct.T* %t, i32 0, i32 1, !dbg !125
  store void (i32)* @func, void (i32)** %funcptr2, align 8, !dbg !126
  br label %if.end

if.end:                                           ; preds = %if.else, %if.then
  call void @dosomething(%struct.T* %t), !dbg !127
  %funcptr3 = getelementptr inbounds %struct.T, %struct.T* %t, i32 0, i32 1, !dbg !128
  %4 = load void (i32)*, void (i32)** %funcptr3, align 8, !dbg !128
  call void %4(i32 23), !dbg !129
  ret i32 0, !dbg !130
}

; Function Attrs: nounwind
declare void @llvm.var.annotation(i8*, i8*, i8*, i32) #3

attributes #0 = { noinline nounwind uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { nounwind readnone speculatable }
attributes #2 = { "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #3 = { nounwind }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!9, !10, !11}
!llvm.ident = !{!12}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "val1", scope: !2, file: !3, line: 15, type: !8, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "clang version 7.0.0 (trunk) (llvm/trunk 333727)", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, enums: !4, globals: !5)
!3 = !DIFile(filename: "test.c", directory: "/mnt/Projects/LLVM-custom/test/Datarand")
!4 = !{}
!5 = !{!0, !6}
!6 = !DIGlobalVariableExpression(var: !7, expr: !DIExpression())
!7 = distinct !DIGlobalVariable(name: "val2", scope: !2, file: !3, line: 16, type: !8, isLocal: false, isDefinition: true)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{i32 2, !"Dwarf Version", i32 4}
!10 = !{i32 2, !"Debug Info Version", i32 3}
!11 = !{i32 1, !"wchar_size", i32 4}
!12 = !{!"clang version 7.0.0 (trunk) (llvm/trunk 333727)"}
!13 = distinct !DISubprogram(name: "printStudent", scope: !3, file: !3, line: 18, type: !14, isLocal: false, isDefinition: true, scopeLine: 18, flags: DIFlagPrototyped, isOptimized: false, unit: !2, retainedNodes: !4)
!14 = !DISubroutineType(types: !15)
!15 = !{null, !16}
!16 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !17, size: 64)
!17 = !DIDerivedType(tag: DW_TAG_typedef, name: "Student", file: !3, line: 13, baseType: !18)
!18 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "Student", file: !3, line: 10, size: 832, elements: !19)
!19 = !{!20, !21}
!20 = !DIDerivedType(tag: DW_TAG_member, name: "id", scope: !18, file: !3, line: 11, baseType: !8, size: 32)
!21 = !DIDerivedType(tag: DW_TAG_member, name: "name", scope: !18, file: !3, line: 12, baseType: !22, size: 800, offset: 32)
!22 = !DICompositeType(tag: DW_TAG_array_type, baseType: !23, size: 800, elements: !24)
!23 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!24 = !{!25}
!25 = !DISubrange(count: 100)
!26 = !DILocalVariable(name: "sptr", arg: 1, scope: !13, file: !3, line: 18, type: !16)
!27 = !DILocation(line: 18, column: 28, scope: !13)
!28 = !DILocation(line: 19, column: 25, scope: !13)
!29 = !DILocation(line: 19, column: 31, scope: !13)
!30 = !DILocation(line: 19, column: 5, scope: !13)
!31 = !DILocation(line: 20, column: 27, scope: !13)
!32 = !DILocation(line: 20, column: 33, scope: !13)
!33 = !DILocation(line: 20, column: 5, scope: !13)
!34 = !DILocation(line: 21, column: 1, scope: !13)
!35 = distinct !DISubprogram(name: "func", scope: !3, file: !3, line: 23, type: !36, isLocal: false, isDefinition: true, scopeLine: 23, flags: DIFlagPrototyped, isOptimized: false, unit: !2, retainedNodes: !4)
!36 = !DISubroutineType(types: !37)
!37 = !{null, !8}
!38 = !DILocalVariable(name: "a", arg: 1, scope: !35, file: !3, line: 23, type: !8)
!39 = !DILocation(line: 23, column: 15, scope: !35)
!40 = !DILocalVariable(name: "k", scope: !35, file: !3, line: 24, type: !8)
!41 = !DILocation(line: 24, column: 9, scope: !35)
!42 = !DILocalVariable(name: "d", scope: !35, file: !3, line: 25, type: !8)
!43 = !DILocation(line: 25, column: 9, scope: !35)
!44 = !DILocalVariable(name: "res", scope: !35, file: !3, line: 26, type: !8)
!45 = !DILocation(line: 26, column: 9, scope: !35)
!46 = !DILocation(line: 26, column: 15, scope: !35)
!47 = !DILocation(line: 26, column: 19, scope: !35)
!48 = !DILocation(line: 26, column: 17, scope: !35)
!49 = !DILocation(line: 26, column: 23, scope: !35)
!50 = !DILocation(line: 26, column: 21, scope: !35)
!51 = !DILocation(line: 27, column: 20, scope: !35)
!52 = !DILocation(line: 27, column: 5, scope: !35)
!53 = !DILocation(line: 28, column: 1, scope: !35)
!54 = distinct !DISubprogram(name: "gunc", scope: !3, file: !3, line: 30, type: !36, isLocal: false, isDefinition: true, scopeLine: 30, flags: DIFlagPrototyped, isOptimized: false, unit: !2, retainedNodes: !4)
!55 = !DILocalVariable(name: "a", arg: 1, scope: !54, file: !3, line: 30, type: !8)
!56 = !DILocation(line: 30, column: 15, scope: !54)
!57 = !DILocalVariable(name: "k", scope: !54, file: !3, line: 31, type: !8)
!58 = !DILocation(line: 31, column: 9, scope: !54)
!59 = !DILocalVariable(name: "d", scope: !54, file: !3, line: 32, type: !8)
!60 = !DILocation(line: 32, column: 9, scope: !54)
!61 = !DILocalVariable(name: "res", scope: !54, file: !3, line: 33, type: !8)
!62 = !DILocation(line: 33, column: 9, scope: !54)
!63 = !DILocation(line: 33, column: 15, scope: !54)
!64 = !DILocation(line: 33, column: 19, scope: !54)
!65 = !DILocation(line: 33, column: 17, scope: !54)
!66 = !DILocation(line: 33, column: 23, scope: !54)
!67 = !DILocation(line: 33, column: 21, scope: !54)
!68 = !DILocation(line: 34, column: 20, scope: !54)
!69 = !DILocation(line: 34, column: 5, scope: !54)
!70 = !DILocation(line: 35, column: 1, scope: !54)
!71 = distinct !DISubprogram(name: "dosomething", scope: !3, file: !3, line: 37, type: !72, isLocal: false, isDefinition: true, scopeLine: 37, flags: DIFlagPrototyped, isOptimized: false, unit: !2, retainedNodes: !4)
!72 = !DISubroutineType(types: !73)
!73 = !{null, !74}
!74 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !75, size: 64)
!75 = !DIDerivedType(tag: DW_TAG_typedef, name: "T", file: !3, line: 8, baseType: !76)
!76 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "T", file: !3, line: 5, size: 128, elements: !77)
!77 = !{!78, !79}
!78 = !DIDerivedType(tag: DW_TAG_member, name: "id", scope: !76, file: !3, line: 6, baseType: !8, size: 32)
!79 = !DIDerivedType(tag: DW_TAG_member, name: "funcptr", scope: !76, file: !3, line: 7, baseType: !80, size: 64, offset: 64)
!80 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !36, size: 64)
!81 = !DILocalVariable(name: "tptr", arg: 1, scope: !71, file: !3, line: 37, type: !74)
!82 = !DILocation(line: 37, column: 21, scope: !71)
!83 = !DILocation(line: 38, column: 8, scope: !71)
!84 = !DILocation(line: 38, column: 14, scope: !71)
!85 = !DILocation(line: 38, column: 5, scope: !71)
!86 = !DILocation(line: 39, column: 1, scope: !71)
!87 = distinct !DISubprogram(name: "main", scope: !3, file: !3, line: 41, type: !88, isLocal: false, isDefinition: true, scopeLine: 41, flags: DIFlagPrototyped, isOptimized: false, unit: !2, retainedNodes: !4)
!88 = !DISubroutineType(types: !89)
!89 = !{!8}
!90 = !DILocalVariable(name: "t", scope: !87, file: !3, line: 42, type: !75)
!91 = !DILocation(line: 42, column: 7, scope: !87)
!92 = !DILocation(line: 43, column: 7, scope: !87)
!93 = !DILocation(line: 43, column: 10, scope: !87)
!94 = !DILocalVariable(name: "stud", scope: !87, file: !3, line: 44, type: !17)
!95 = !DILocation(line: 44, column: 13, scope: !87)
!96 = !DILocalVariable(name: "fptr", scope: !87, file: !3, line: 45, type: !80)
!97 = !DILocation(line: 45, column: 12, scope: !87)
!98 = !DILocalVariable(name: "iptr", scope: !87, file: !3, line: 46, type: !99)
!99 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !8, size: 64)
!100 = !DILocation(line: 46, column: 20, scope: !87)
!101 = !DILocation(line: 46, column: 5, scope: !87)
!102 = !DILocalVariable(name: "k", scope: !87, file: !3, line: 47, type: !8)
!103 = !DILocation(line: 47, column: 9, scope: !87)
!104 = !DILocalVariable(name: "j", scope: !87, file: !3, line: 48, type: !8)
!105 = !DILocation(line: 48, column: 9, scope: !87)
!106 = !DILocation(line: 48, column: 13, scope: !87)
!107 = !DILocation(line: 48, column: 15, scope: !87)
!108 = !DILocation(line: 49, column: 5, scope: !87)
!109 = !DILocation(line: 50, column: 21, scope: !87)
!110 = !DILocation(line: 50, column: 24, scope: !87)
!111 = !DILocation(line: 50, column: 5, scope: !87)
!112 = !DILocation(line: 51, column: 10, scope: !113)
!113 = distinct !DILexicalBlock(scope: !87, file: !3, line: 51, column: 10)
!114 = !DILocation(line: 51, column: 12, scope: !113)
!115 = !DILocation(line: 51, column: 10, scope: !87)
!116 = !DILocation(line: 52, column: 14, scope: !117)
!117 = distinct !DILexicalBlock(scope: !113, file: !3, line: 51, column: 19)
!118 = !DILocation(line: 53, column: 14, scope: !117)
!119 = !DILocation(line: 54, column: 11, scope: !117)
!120 = !DILocation(line: 54, column: 19, scope: !117)
!121 = !DILocation(line: 55, column: 5, scope: !117)
!122 = !DILocation(line: 56, column: 14, scope: !123)
!123 = distinct !DILexicalBlock(scope: !113, file: !3, line: 55, column: 12)
!124 = !DILocation(line: 57, column: 14, scope: !123)
!125 = !DILocation(line: 58, column: 11, scope: !123)
!126 = !DILocation(line: 58, column: 19, scope: !123)
!127 = !DILocation(line: 61, column: 5, scope: !87)
!128 = !DILocation(line: 62, column: 10, scope: !87)
!129 = !DILocation(line: 62, column: 5, scope: !87)
!130 = !DILocation(line: 63, column: 5, scope: !87)
