; ModuleID = 'testdemand.c'
source_filename = "testdemand.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

@.str = private unnamed_addr constant [10 x i8] c"sensitive\00", section "llvm.metadata"
@.str.1 = private unnamed_addr constant [13 x i8] c"testdemand.c\00", section "llvm.metadata"
@.str.2 = private unnamed_addr constant [4 x i8] c"%d\0A\00", align 1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main() #0 !dbg !7 {
entry:
  %retval = alloca i32, align 4
  %a = alloca i32, align 4
  %b = alloca i32, align 4
  %p1 = alloca i32*, align 8
  %p2 = alloca i32*, align 8
  store i32 0, i32* %retval, align 4
  call void @llvm.dbg.declare(metadata i32* %a, metadata !11, metadata !DIExpression()), !dbg !12
  %a1 = bitcast i32* %a to i8*, !dbg !13
  call void @llvm.var.annotation(i8* %a1, i8* getelementptr inbounds ([10 x i8], [10 x i8]* @.str, i32 0, i32 0), i8* getelementptr inbounds ([13 x i8], [13 x i8]* @.str.1, i32 0, i32 0), i32 5), !dbg !13
  store i32 10, i32* %a, align 4, !dbg !12
  call void @llvm.dbg.declare(metadata i32* %b, metadata !14, metadata !DIExpression()), !dbg !15
  store i32 30, i32* %b, align 4, !dbg !15
  call void @llvm.dbg.declare(metadata i32** %p1, metadata !16, metadata !DIExpression()), !dbg !18
  store i32* %a, i32** %p1, align 8, !dbg !18
  call void @llvm.dbg.declare(metadata i32** %p2, metadata !19, metadata !DIExpression()), !dbg !20
  store i32* %b, i32** %p2, align 8, !dbg !20
  %0 = load i32*, i32** %p1, align 8, !dbg !21
  %1 = load i32, i32* %0, align 4, !dbg !22
  %call = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str.2, i32 0, i32 0), i32 %1), !dbg !23
  %2 = load i32*, i32** %p2, align 8, !dbg !24
  %3 = load i32, i32* %2, align 4, !dbg !25
  %call2 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str.2, i32 0, i32 0), i32 %3), !dbg !26
  ret i32 0, !dbg !27
}

; Function Attrs: nounwind readnone speculatable
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: nounwind
declare void @llvm.var.annotation(i8*, i8*, i8*, i32) #2

declare dso_local i32 @printf(i8*, ...) #3

attributes #0 = { noinline nounwind optnone uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { nounwind readnone speculatable }
attributes #2 = { nounwind }
attributes #3 = { "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!3, !4, !5}
!llvm.ident = !{!6}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "clang version 7.0.0 (trunk) (llvm/trunk 333727)", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, enums: !2)
!1 = !DIFile(filename: "testdemand.c", directory: "/mnt/Projects/LLVM-custom/test/Datarand")
!2 = !{}
!3 = !{i32 2, !"Dwarf Version", i32 4}
!4 = !{i32 2, !"Debug Info Version", i32 3}
!5 = !{i32 1, !"wchar_size", i32 4}
!6 = !{!"clang version 7.0.0 (trunk) (llvm/trunk 333727)"}
!7 = distinct !DISubprogram(name: "main", scope: !1, file: !1, line: 4, type: !8, isLocal: false, isDefinition: true, scopeLine: 4, flags: DIFlagPrototyped, isOptimized: false, unit: !0, retainedNodes: !2)
!8 = !DISubroutineType(types: !9)
!9 = !{!10}
!10 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!11 = !DILocalVariable(name: "a", scope: !7, file: !1, line: 5, type: !10)
!12 = !DILocation(line: 5, column: 19, scope: !7)
!13 = !DILocation(line: 5, column: 5, scope: !7)
!14 = !DILocalVariable(name: "b", scope: !7, file: !1, line: 6, type: !10)
!15 = !DILocation(line: 6, column: 9, scope: !7)
!16 = !DILocalVariable(name: "p1", scope: !7, file: !1, line: 7, type: !17)
!17 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !10, size: 64)
!18 = !DILocation(line: 7, column: 10, scope: !7)
!19 = !DILocalVariable(name: "p2", scope: !7, file: !1, line: 8, type: !17)
!20 = !DILocation(line: 8, column: 10, scope: !7)
!21 = !DILocation(line: 10, column: 21, scope: !7)
!22 = !DILocation(line: 10, column: 20, scope: !7)
!23 = !DILocation(line: 10, column: 5, scope: !7)
!24 = !DILocation(line: 11, column: 21, scope: !7)
!25 = !DILocation(line: 11, column: 20, scope: !7)
!26 = !DILocation(line: 11, column: 5, scope: !7)
!27 = !DILocation(line: 12, column: 5, scope: !7)
