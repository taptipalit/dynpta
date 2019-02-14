; ModuleID = 'demand_fields.c'
source_filename = "demand_fields.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

%struct.Student = type { i32*, i32, [10 x i8] }

@.str = private unnamed_addr constant [10 x i8] c"sensitive\00", section "llvm.metadata"
@.str.1 = private unnamed_addr constant [16 x i8] c"demand_fields.c\00", section "llvm.metadata"
@.str.2 = private unnamed_addr constant [4 x i8] c"%d\0A\00", align 1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main() #0 !dbg !7 {
entry:
  %retval = alloca i32, align 4
  %a = alloca i32, align 4
  %stud = alloca %struct.Student, align 8
  %localpointer = alloca i32*, align 8
  %sptr = alloca %struct.Student*, align 8
  %b = alloca i32, align 4
  %p1 = alloca i32*, align 8
  %p2 = alloca i32*, align 8
  store i32 0, i32* %retval, align 4
  call void @llvm.dbg.declare(metadata i32* %a, metadata !11, metadata !DIExpression()), !dbg !12
  %a1 = bitcast i32* %a to i8*, !dbg !13
  call void @llvm.var.annotation(i8* %a1, i8* getelementptr inbounds ([10 x i8], [10 x i8]* @.str, i32 0, i32 0), i8* getelementptr inbounds ([16 x i8], [16 x i8]* @.str.1, i32 0, i32 0), i32 11), !dbg !13
  store i32 10, i32* %a, align 4, !dbg !12
  call void @llvm.dbg.declare(metadata %struct.Student* %stud, metadata !14, metadata !DIExpression()), !dbg !26
  call void @llvm.dbg.declare(metadata i32** %localpointer, metadata !27, metadata !DIExpression()), !dbg !28
  %pointer = getelementptr inbounds %struct.Student, %struct.Student* %stud, i32 0, i32 0, !dbg !29
  store i32* %a, i32** %pointer, align 8, !dbg !30
  %id = getelementptr inbounds %struct.Student, %struct.Student* %stud, i32 0, i32 1, !dbg !31
  store i32 20, i32* %id, align 8, !dbg !32
  call void @llvm.dbg.declare(metadata %struct.Student** %sptr, metadata !33, metadata !DIExpression()), !dbg !35
  store %struct.Student* %stud, %struct.Student** %sptr, align 8, !dbg !36
  call void @llvm.dbg.declare(metadata i32* %b, metadata !37, metadata !DIExpression()), !dbg !38
  store i32 30, i32* %b, align 4, !dbg !38
  call void @llvm.dbg.declare(metadata i32** %p1, metadata !39, metadata !DIExpression()), !dbg !40
  store i32* %a, i32** %p1, align 8, !dbg !40
  call void @llvm.dbg.declare(metadata i32** %p2, metadata !41, metadata !DIExpression()), !dbg !42
  store i32* %b, i32** %p2, align 8, !dbg !42
  %0 = load i32*, i32** %p1, align 8, !dbg !43
  %1 = load i32, i32* %0, align 4, !dbg !44
  %call = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str.2, i32 0, i32 0), i32 %1), !dbg !45
  %2 = load i32*, i32** %p2, align 8, !dbg !46
  %3 = load i32, i32* %2, align 4, !dbg !47
  %call2 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str.2, i32 0, i32 0), i32 %3), !dbg !48
  %4 = load %struct.Student*, %struct.Student** %sptr, align 8, !dbg !49
  %pointer3 = getelementptr inbounds %struct.Student, %struct.Student* %4, i32 0, i32 0, !dbg !50
  %5 = load i32*, i32** %pointer3, align 8, !dbg !50
  %6 = load i32, i32* %5, align 4, !dbg !51
  %call4 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str.2, i32 0, i32 0), i32 %6), !dbg !52
  %id5 = getelementptr inbounds %struct.Student, %struct.Student* %stud, i32 0, i32 1, !dbg !53
  %7 = load i32, i32* %id5, align 8, !dbg !53
  %call6 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str.2, i32 0, i32 0), i32 %7), !dbg !54
  %8 = load %struct.Student*, %struct.Student** %sptr, align 8, !dbg !55
  %pointer7 = getelementptr inbounds %struct.Student, %struct.Student* %8, i32 0, i32 0, !dbg !56
  %9 = load i32*, i32** %pointer7, align 8, !dbg !56
  store i32* %9, i32** %localpointer, align 8, !dbg !57
  %10 = load i32*, i32** %localpointer, align 8, !dbg !58
  %call8 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str.2, i32 0, i32 0), i32* %10), !dbg !59
  ret i32 0, !dbg !60
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
!1 = !DIFile(filename: "demand_fields.c", directory: "/mnt/Projects/LLVM-custom/test/Datarand")
!2 = !{}
!3 = !{i32 2, !"Dwarf Version", i32 4}
!4 = !{i32 2, !"Debug Info Version", i32 3}
!5 = !{i32 1, !"wchar_size", i32 4}
!6 = !{!"clang version 7.0.0 (trunk) (llvm/trunk 333727)"}
!7 = distinct !DISubprogram(name: "main", scope: !1, file: !1, line: 10, type: !8, isLocal: false, isDefinition: true, scopeLine: 10, flags: DIFlagPrototyped, isOptimized: false, unit: !0, retainedNodes: !2)
!8 = !DISubroutineType(types: !9)
!9 = !{!10}
!10 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!11 = !DILocalVariable(name: "a", scope: !7, file: !1, line: 11, type: !10)
!12 = !DILocation(line: 11, column: 19, scope: !7)
!13 = !DILocation(line: 11, column: 5, scope: !7)
!14 = !DILocalVariable(name: "stud", scope: !7, file: !1, line: 12, type: !15)
!15 = !DIDerivedType(tag: DW_TAG_typedef, name: "Student", file: !1, line: 8, baseType: !16)
!16 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "Student", file: !1, line: 4, size: 192, elements: !17)
!17 = !{!18, !20, !21}
!18 = !DIDerivedType(tag: DW_TAG_member, name: "pointer", scope: !16, file: !1, line: 5, baseType: !19, size: 64)
!19 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !10, size: 64)
!20 = !DIDerivedType(tag: DW_TAG_member, name: "id", scope: !16, file: !1, line: 6, baseType: !10, size: 32, offset: 64)
!21 = !DIDerivedType(tag: DW_TAG_member, name: "name", scope: !16, file: !1, line: 7, baseType: !22, size: 80, offset: 96)
!22 = !DICompositeType(tag: DW_TAG_array_type, baseType: !23, size: 80, elements: !24)
!23 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!24 = !{!25}
!25 = !DISubrange(count: 10)
!26 = !DILocation(line: 12, column: 13, scope: !7)
!27 = !DILocalVariable(name: "localpointer", scope: !7, file: !1, line: 13, type: !19)
!28 = !DILocation(line: 13, column: 10, scope: !7)
!29 = !DILocation(line: 14, column: 10, scope: !7)
!30 = !DILocation(line: 14, column: 18, scope: !7)
!31 = !DILocation(line: 15, column: 10, scope: !7)
!32 = !DILocation(line: 15, column: 13, scope: !7)
!33 = !DILocalVariable(name: "sptr", scope: !7, file: !1, line: 16, type: !34)
!34 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !15, size: 64)
!35 = !DILocation(line: 16, column: 14, scope: !7)
!36 = !DILocation(line: 17, column: 10, scope: !7)
!37 = !DILocalVariable(name: "b", scope: !7, file: !1, line: 18, type: !10)
!38 = !DILocation(line: 18, column: 9, scope: !7)
!39 = !DILocalVariable(name: "p1", scope: !7, file: !1, line: 19, type: !19)
!40 = !DILocation(line: 19, column: 10, scope: !7)
!41 = !DILocalVariable(name: "p2", scope: !7, file: !1, line: 20, type: !19)
!42 = !DILocation(line: 20, column: 10, scope: !7)
!43 = !DILocation(line: 22, column: 21, scope: !7)
!44 = !DILocation(line: 22, column: 20, scope: !7)
!45 = !DILocation(line: 22, column: 5, scope: !7)
!46 = !DILocation(line: 23, column: 21, scope: !7)
!47 = !DILocation(line: 23, column: 20, scope: !7)
!48 = !DILocation(line: 23, column: 5, scope: !7)
!49 = !DILocation(line: 24, column: 22, scope: !7)
!50 = !DILocation(line: 24, column: 28, scope: !7)
!51 = !DILocation(line: 24, column: 20, scope: !7)
!52 = !DILocation(line: 24, column: 5, scope: !7)
!53 = !DILocation(line: 25, column: 25, scope: !7)
!54 = !DILocation(line: 25, column: 5, scope: !7)
!55 = !DILocation(line: 26, column: 20, scope: !7)
!56 = !DILocation(line: 26, column: 26, scope: !7)
!57 = !DILocation(line: 26, column: 18, scope: !7)
!58 = !DILocation(line: 27, column: 20, scope: !7)
!59 = !DILocation(line: 27, column: 5, scope: !7)
!60 = !DILocation(line: 28, column: 5, scope: !7)
