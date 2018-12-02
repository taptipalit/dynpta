; ModuleID = 'test_inst.bc'
source_filename = "test.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

%struct.T = type { i32, void (i32)* }

@val1 = dso_local global i32 200, align 4, !dbg !0
@val2 = dso_local global i32 300, align 4, !dbg !6
@.str = private unnamed_addr constant [4 x i8] c"%d\0A\00", align 1
@.str.1 = private unnamed_addr constant [10 x i8] c"sensitive\00", section "llvm.metadata"
@.str.2 = private unnamed_addr constant [7 x i8] c"test.c\00", section "llvm.metadata"
@.str.3 = private unnamed_addr constant [6 x i8] c"%d %d\00", align 1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @func(i32 %a) #0 !dbg !13 {
entry:
  %a.addr = alloca i32, align 4
  %k = alloca i32, align 4
  %d = alloca i32, align 4
  %res = alloca i32, align 4
  store i32 %a, i32* %a.addr, align 4
  call void @llvm.dbg.declare(metadata i32* %a.addr, metadata !16, metadata !DIExpression()), !dbg !17
  call void @llvm.dbg.declare(metadata i32* %k, metadata !18, metadata !DIExpression()), !dbg !19
  store i32 10, i32* %k, align 4, !dbg !19
  call void @llvm.dbg.declare(metadata i32* %d, metadata !20, metadata !DIExpression()), !dbg !21
  store i32 100, i32* %d, align 4, !dbg !21
  call void @llvm.dbg.declare(metadata i32* %res, metadata !22, metadata !DIExpression()), !dbg !23
  %0 = load i32, i32* %a.addr, align 4, !dbg !24
  %1 = load i32, i32* %k, align 4, !dbg !25
  %add = add nsw i32 %0, %1, !dbg !26
  %2 = load i32, i32* %d, align 4, !dbg !27
  %add1 = add nsw i32 %add, %2, !dbg !28
  store i32 %add1, i32* %res, align 4, !dbg !23
  %3 = load i32, i32* %res, align 4, !dbg !29
  %4 = getelementptr [4 x i8], [4 x i8]* @.str, i32 0, i32 0
  %call = call i32 (i8*, ...) @printf(i8* %4, i32 %3), !dbg !30
  ret void, !dbg !31
}

; Function Attrs: nounwind readnone speculatable
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

declare dso_local i32 @printf(i8*, ...) #2

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @gunc(i32 %a) #0 !dbg !32 {
entry:
  %a.addr = alloca i32, align 4
  %k = alloca i32, align 4
  %d = alloca i32, align 4
  %res = alloca i32, align 4
  store i32 %a, i32* %a.addr, align 4
  call void @llvm.dbg.declare(metadata i32* %a.addr, metadata !33, metadata !DIExpression()), !dbg !34
  call void @llvm.dbg.declare(metadata i32* %k, metadata !35, metadata !DIExpression()), !dbg !36
  store i32 10, i32* %k, align 4, !dbg !36
  call void @llvm.dbg.declare(metadata i32* %d, metadata !37, metadata !DIExpression()), !dbg !38
  store i32 200, i32* %d, align 4, !dbg !38
  call void @llvm.dbg.declare(metadata i32* %res, metadata !39, metadata !DIExpression()), !dbg !40
  %0 = load i32, i32* %d, align 4, !dbg !41
  %1 = load i32, i32* %k, align 4, !dbg !42
  %sub = sub nsw i32 %0, %1, !dbg !43
  %2 = load i32, i32* %a.addr, align 4, !dbg !44
  %sub1 = sub nsw i32 %sub, %2, !dbg !45
  store i32 %sub1, i32* %res, align 4, !dbg !40
  %3 = load i32, i32* %res, align 4, !dbg !46
  %4 = getelementptr [4 x i8], [4 x i8]* @.str, i32 0, i32 0
  %call = call i32 (i8*, ...) @printf(i8* %4, i32 %3), !dbg !47
  ret void, !dbg !48
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @dosomething(%struct.T* %tptr) #0 !dbg !49 {
entry:
  %tptr.addr = alloca %struct.T*, align 8
  store %struct.T* %tptr, %struct.T** %tptr.addr, align 8
  call void @llvm.dbg.declare(metadata %struct.T** %tptr.addr, metadata !59, metadata !DIExpression()), !dbg !60
  %0 = load %struct.T*, %struct.T** %tptr.addr, align 8, !dbg !61
  %funcptr = getelementptr inbounds %struct.T, %struct.T* %0, i32 0, i32 1, !dbg !62
  %1 = load void (i32)*, void (i32)** %funcptr, align 8, !dbg !62
  call void %1(i32 200), !dbg !63
  ret void, !dbg !64
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main() #0 !dbg !65 {
entry:
  %retval = alloca i32, align 4
  %t = alloca %struct.T, align 8
  %fptr = alloca void (i32)*, align 8
  %iptr = alloca i32*, align 8
  %k = alloca i32, align 4
  %j = alloca i32, align 4
  store i32 0, i32* %retval, align 4
  call void @llvm.dbg.declare(metadata %struct.T* %t, metadata !68, metadata !DIExpression()), !dbg !69
  %id = getelementptr inbounds %struct.T, %struct.T* %t, i32 0, i32 0, !dbg !70
  store i32 100, i32* %id, align 8, !dbg !71
  call void @llvm.dbg.declare(metadata void (i32)** %fptr, metadata !72, metadata !DIExpression()), !dbg !73
  call void @llvm.dbg.declare(metadata i32** %iptr, metadata !74, metadata !DIExpression()), !dbg !76
  %iptr1 = bitcast i32** %iptr to i8*, !dbg !77
  %0 = getelementptr [10 x i8], [10 x i8]* @.str.1, i32 0, i32 0
  %1 = getelementptr [7 x i8], [7 x i8]* @.str.2, i32 0, i32 0
  call void @llvm.var.annotation(i8* %iptr1, i8* %0, i8* %1, i32 35), !dbg !77
  call void @llvm.dbg.declare(metadata i32* %k, metadata !78, metadata !DIExpression()), !dbg !79
  store i32 0, i32* %k, align 4, !dbg !79
  call void @llvm.dbg.declare(metadata i32* %j, metadata !80, metadata !DIExpression()), !dbg !81
  %2 = load i32, i32* %k, align 4, !dbg !82
  %add = add nsw i32 %2, 10, !dbg !83
  store i32 %add, i32* %j, align 4, !dbg !81
  %3 = load i32, i32* %k, align 4, !dbg !84
  %4 = load i32, i32* %j, align 4, !dbg !85
  %5 = getelementptr [6 x i8], [6 x i8]* @.str.3, i32 0, i32 0
  %call = call i32 (i8*, ...) @printf(i8* %5, i32 %3, i32 %4), !dbg !86
  %6 = load i32, i32* %j, align 4, !dbg !87
  %cmp = icmp slt i32 %6, 100, !dbg !89
  br i1 %cmp, label %if.then, label %if.else, !dbg !90

if.then:                                          ; preds = %entry
  store void (i32)* @func, void (i32)** %fptr, align 8, !dbg !91
  store i32* @val1, i32** %iptr, align 8, !dbg !93
  %funcptr = getelementptr inbounds %struct.T, %struct.T* %t, i32 0, i32 1, !dbg !94
  store void (i32)* @gunc, void (i32)** %funcptr, align 8, !dbg !95
  br label %if.end, !dbg !96

if.else:                                          ; preds = %entry
  store void (i32)* @gunc, void (i32)** %fptr, align 8, !dbg !97
  store i32* @val2, i32** %iptr, align 8, !dbg !99
  %funcptr2 = getelementptr inbounds %struct.T, %struct.T* %t, i32 0, i32 1, !dbg !100
  store void (i32)* @func, void (i32)** %funcptr2, align 8, !dbg !101
  br label %if.end

if.end:                                           ; preds = %if.else, %if.then
  call void @dosomething(%struct.T* %t), !dbg !102
  %funcptr3 = getelementptr inbounds %struct.T, %struct.T* %t, i32 0, i32 1, !dbg !103
  %7 = load void (i32)*, void (i32)** %funcptr3, align 8, !dbg !103
  call void %7(i32 23), !dbg !104
  ret i32 0, !dbg !105
}

; Function Attrs: nounwind
declare void @llvm.var.annotation(i8*, i8*, i8*, i32) #3

attributes #0 = { noinline nounwind optnone uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { nounwind readnone speculatable }
attributes #2 = { "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #3 = { nounwind }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!9, !10, !11}
!llvm.ident = !{!12}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "val1", scope: !2, file: !3, line: 10, type: !8, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "clang version 7.0.0 (trunk) (llvm/trunk 333727)", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, enums: !4, globals: !5)
!3 = !DIFile(filename: "test.c", directory: "/mnt/Projects/LLVM-custom/test/Datarand")
!4 = !{}
!5 = !{!0, !6}
!6 = !DIGlobalVariableExpression(var: !7, expr: !DIExpression())
!7 = distinct !DIGlobalVariable(name: "val2", scope: !2, file: !3, line: 11, type: !8, isLocal: false, isDefinition: true)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{i32 2, !"Dwarf Version", i32 4}
!10 = !{i32 2, !"Debug Info Version", i32 3}
!11 = !{i32 1, !"wchar_size", i32 4}
!12 = !{!"clang version 7.0.0 (trunk) (llvm/trunk 333727)"}
!13 = distinct !DISubprogram(name: "func", scope: !3, file: !3, line: 13, type: !14, isLocal: false, isDefinition: true, scopeLine: 13, flags: DIFlagPrototyped, isOptimized: false, unit: !2, retainedNodes: !4)
!14 = !DISubroutineType(types: !15)
!15 = !{null, !8}
!16 = !DILocalVariable(name: "a", arg: 1, scope: !13, file: !3, line: 13, type: !8)
!17 = !DILocation(line: 13, column: 15, scope: !13)
!18 = !DILocalVariable(name: "k", scope: !13, file: !3, line: 14, type: !8)
!19 = !DILocation(line: 14, column: 9, scope: !13)
!20 = !DILocalVariable(name: "d", scope: !13, file: !3, line: 15, type: !8)
!21 = !DILocation(line: 15, column: 9, scope: !13)
!22 = !DILocalVariable(name: "res", scope: !13, file: !3, line: 16, type: !8)
!23 = !DILocation(line: 16, column: 9, scope: !13)
!24 = !DILocation(line: 16, column: 15, scope: !13)
!25 = !DILocation(line: 16, column: 19, scope: !13)
!26 = !DILocation(line: 16, column: 17, scope: !13)
!27 = !DILocation(line: 16, column: 23, scope: !13)
!28 = !DILocation(line: 16, column: 21, scope: !13)
!29 = !DILocation(line: 17, column: 20, scope: !13)
!30 = !DILocation(line: 17, column: 5, scope: !13)
!31 = !DILocation(line: 18, column: 1, scope: !13)
!32 = distinct !DISubprogram(name: "gunc", scope: !3, file: !3, line: 20, type: !14, isLocal: false, isDefinition: true, scopeLine: 20, flags: DIFlagPrototyped, isOptimized: false, unit: !2, retainedNodes: !4)
!33 = !DILocalVariable(name: "a", arg: 1, scope: !32, file: !3, line: 20, type: !8)
!34 = !DILocation(line: 20, column: 15, scope: !32)
!35 = !DILocalVariable(name: "k", scope: !32, file: !3, line: 21, type: !8)
!36 = !DILocation(line: 21, column: 9, scope: !32)
!37 = !DILocalVariable(name: "d", scope: !32, file: !3, line: 22, type: !8)
!38 = !DILocation(line: 22, column: 9, scope: !32)
!39 = !DILocalVariable(name: "res", scope: !32, file: !3, line: 23, type: !8)
!40 = !DILocation(line: 23, column: 9, scope: !32)
!41 = !DILocation(line: 23, column: 15, scope: !32)
!42 = !DILocation(line: 23, column: 19, scope: !32)
!43 = !DILocation(line: 23, column: 17, scope: !32)
!44 = !DILocation(line: 23, column: 23, scope: !32)
!45 = !DILocation(line: 23, column: 21, scope: !32)
!46 = !DILocation(line: 24, column: 20, scope: !32)
!47 = !DILocation(line: 24, column: 5, scope: !32)
!48 = !DILocation(line: 25, column: 1, scope: !32)
!49 = distinct !DISubprogram(name: "dosomething", scope: !3, file: !3, line: 27, type: !50, isLocal: false, isDefinition: true, scopeLine: 27, flags: DIFlagPrototyped, isOptimized: false, unit: !2, retainedNodes: !4)
!50 = !DISubroutineType(types: !51)
!51 = !{null, !52}
!52 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !53, size: 64)
!53 = !DIDerivedType(tag: DW_TAG_typedef, name: "T", file: !3, line: 8, baseType: !54)
!54 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "T", file: !3, line: 5, size: 128, elements: !55)
!55 = !{!56, !57}
!56 = !DIDerivedType(tag: DW_TAG_member, name: "id", scope: !54, file: !3, line: 6, baseType: !8, size: 32)
!57 = !DIDerivedType(tag: DW_TAG_member, name: "funcptr", scope: !54, file: !3, line: 7, baseType: !58, size: 64, offset: 64)
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !14, size: 64)
!59 = !DILocalVariable(name: "tptr", arg: 1, scope: !49, file: !3, line: 27, type: !52)
!60 = !DILocation(line: 27, column: 21, scope: !49)
!61 = !DILocation(line: 28, column: 8, scope: !49)
!62 = !DILocation(line: 28, column: 14, scope: !49)
!63 = !DILocation(line: 28, column: 5, scope: !49)
!64 = !DILocation(line: 29, column: 1, scope: !49)
!65 = distinct !DISubprogram(name: "main", scope: !3, file: !3, line: 31, type: !66, isLocal: false, isDefinition: true, scopeLine: 31, flags: DIFlagPrototyped, isOptimized: false, unit: !2, retainedNodes: !4)
!66 = !DISubroutineType(types: !67)
!67 = !{!8}
!68 = !DILocalVariable(name: "t", scope: !65, file: !3, line: 32, type: !53)
!69 = !DILocation(line: 32, column: 7, scope: !65)
!70 = !DILocation(line: 33, column: 7, scope: !65)
!71 = !DILocation(line: 33, column: 10, scope: !65)
!72 = !DILocalVariable(name: "fptr", scope: !65, file: !3, line: 34, type: !58)
!73 = !DILocation(line: 34, column: 12, scope: !65)
!74 = !DILocalVariable(name: "iptr", scope: !65, file: !3, line: 35, type: !75)
!75 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !8, size: 64)
!76 = !DILocation(line: 35, column: 20, scope: !65)
!77 = !DILocation(line: 35, column: 5, scope: !65)
!78 = !DILocalVariable(name: "k", scope: !65, file: !3, line: 36, type: !8)
!79 = !DILocation(line: 36, column: 9, scope: !65)
!80 = !DILocalVariable(name: "j", scope: !65, file: !3, line: 37, type: !8)
!81 = !DILocation(line: 37, column: 9, scope: !65)
!82 = !DILocation(line: 37, column: 13, scope: !65)
!83 = !DILocation(line: 37, column: 15, scope: !65)
!84 = !DILocation(line: 38, column: 21, scope: !65)
!85 = !DILocation(line: 38, column: 24, scope: !65)
!86 = !DILocation(line: 38, column: 5, scope: !65)
!87 = !DILocation(line: 39, column: 10, scope: !88)
!88 = distinct !DILexicalBlock(scope: !65, file: !3, line: 39, column: 10)
!89 = !DILocation(line: 39, column: 12, scope: !88)
!90 = !DILocation(line: 39, column: 10, scope: !65)
!91 = !DILocation(line: 40, column: 14, scope: !92)
!92 = distinct !DILexicalBlock(scope: !88, file: !3, line: 39, column: 19)
!93 = !DILocation(line: 41, column: 14, scope: !92)
!94 = !DILocation(line: 42, column: 11, scope: !92)
!95 = !DILocation(line: 42, column: 19, scope: !92)
!96 = !DILocation(line: 43, column: 5, scope: !92)
!97 = !DILocation(line: 44, column: 14, scope: !98)
!98 = distinct !DILexicalBlock(scope: !88, file: !3, line: 43, column: 12)
!99 = !DILocation(line: 45, column: 14, scope: !98)
!100 = !DILocation(line: 46, column: 11, scope: !98)
!101 = !DILocation(line: 46, column: 19, scope: !98)
!102 = !DILocation(line: 49, column: 5, scope: !65)
!103 = !DILocation(line: 50, column: 10, scope: !65)
!104 = !DILocation(line: 50, column: 5, scope: !65)
!105 = !DILocation(line: 51, column: 5, scope: !65)
