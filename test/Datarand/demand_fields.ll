; ModuleID = 'demand_fields.c'
source_filename = "demand_fields.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

%struct.Student = type { i32*, i32, [10 x i8] }

@.str = private unnamed_addr constant [10 x i8] c"sensitive\00", section "llvm.metadata"
@.str.1 = private unnamed_addr constant [16 x i8] c"demand_fields.c\00", section "llvm.metadata"
@.str.2 = private unnamed_addr constant [4 x i8] c"%d\0A\00", align 1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main() #0 {
entry:
  %retval = alloca i32, align 4
  %a = alloca i32, align 4
  %stud = alloca %struct.Student, align 8
  %sptr = alloca %struct.Student*, align 8
  %b = alloca i32, align 4
  %p1 = alloca i32*, align 8
  %p2 = alloca i32*, align 8
  store i32 0, i32* %retval, align 4
  %a1 = bitcast i32* %a to i8*
  call void @llvm.var.annotation(i8* %a1, i8* getelementptr inbounds ([10 x i8], [10 x i8]* @.str, i32 0, i32 0), i8* getelementptr inbounds ([16 x i8], [16 x i8]* @.str.1, i32 0, i32 0), i32 11)
  store i32 10, i32* %a, align 4
  %pointer = getelementptr inbounds %struct.Student, %struct.Student* %stud, i32 0, i32 0
  store i32* %a, i32** %pointer, align 8
  %id = getelementptr inbounds %struct.Student, %struct.Student* %stud, i32 0, i32 1
  store i32 20, i32* %id, align 8
  store %struct.Student* %stud, %struct.Student** %sptr, align 8
  store i32 30, i32* %b, align 4
  store i32* %a, i32** %p1, align 8
  store i32* %b, i32** %p2, align 8
  %0 = load i32*, i32** %p1, align 8
  %1 = load i32, i32* %0, align 4
  %call = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str.2, i32 0, i32 0), i32 %1)
  %2 = load i32*, i32** %p2, align 8
  %3 = load i32, i32* %2, align 4
  %call2 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str.2, i32 0, i32 0), i32 %3)
  %4 = load %struct.Student*, %struct.Student** %sptr, align 8
  %pointer3 = getelementptr inbounds %struct.Student, %struct.Student* %4, i32 0, i32 0
  %5 = load i32*, i32** %pointer3, align 8
  %6 = load i32, i32* %5, align 4
  %call4 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str.2, i32 0, i32 0), i32 %6)
  %id5 = getelementptr inbounds %struct.Student, %struct.Student* %stud, i32 0, i32 1
  %7 = load i32, i32* %id5, align 8
  %call6 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str.2, i32 0, i32 0), i32 %7)
  ret i32 0
}

; Function Attrs: nounwind
declare void @llvm.var.annotation(i8*, i8*, i8*, i32) #1

declare dso_local i32 @printf(i8*, ...) #2

attributes #0 = { noinline nounwind optnone uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { nounwind }
attributes #2 = { "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"clang version 7.0.0 (trunk) (llvm/trunk 333727)"}
