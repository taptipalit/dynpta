; ModuleID = 'test.c'
source_filename = "test.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

%struct.T = type { i32, void (i32)* }

@val1 = dso_local global i32 200, align 4
@val2 = dso_local global i32 300, align 4
@.str = private unnamed_addr constant [4 x i8] c"%d\0A\00", align 1
@.str.1 = private unnamed_addr constant [10 x i8] c"sensitive\00", section "llvm.metadata"
@.str.2 = private unnamed_addr constant [7 x i8] c"test.c\00", section "llvm.metadata"
@.str.3 = private unnamed_addr constant [6 x i8] c"%d %d\00", align 1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @f(i32 %a) #0 {
entry:
  %a.addr = alloca i32, align 4
  %k = alloca i32, align 4
  %d = alloca i32, align 4
  %res = alloca i32, align 4
  store i32 %a, i32* %a.addr, align 4
  store i32 10, i32* %k, align 4
  store i32 100, i32* %d, align 4
  %0 = load i32, i32* %a.addr, align 4
  %1 = load i32, i32* %k, align 4
  %add = add nsw i32 %0, %1
  %2 = load i32, i32* %d, align 4
  %add1 = add nsw i32 %add, %2
  store i32 %add1, i32* %res, align 4
  %3 = load i32, i32* %res, align 4
  %call = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str, i32 0, i32 0), i32 %3)
  ret void
}

declare dso_local i32 @printf(i8*, ...) #1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @g(i32 %a) #0 {
entry:
  %a.addr = alloca i32, align 4
  %k = alloca i32, align 4
  %d = alloca i32, align 4
  %res = alloca i32, align 4
  store i32 %a, i32* %a.addr, align 4
  store i32 10, i32* %k, align 4
  store i32 200, i32* %d, align 4
  %0 = load i32, i32* %d, align 4
  %1 = load i32, i32* %k, align 4
  %sub = sub nsw i32 %0, %1
  %2 = load i32, i32* %a.addr, align 4
  %sub1 = sub nsw i32 %sub, %2
  store i32 %sub1, i32* %res, align 4
  %3 = load i32, i32* %res, align 4
  %call = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str, i32 0, i32 0), i32 %3)
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @dosomething(%struct.T* %tptr) #0 {
entry:
  %tptr.addr = alloca %struct.T*, align 8
  store %struct.T* %tptr, %struct.T** %tptr.addr, align 8
  %0 = load %struct.T*, %struct.T** %tptr.addr, align 8
  %funcptr = getelementptr inbounds %struct.T, %struct.T* %0, i32 0, i32 1
  %1 = load void (i32)*, void (i32)** %funcptr, align 8
  call void %1(i32 200)
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main() #0 {
entry:
  %retval = alloca i32, align 4
  %t = alloca %struct.T, align 8
  %fptr = alloca void (i32)*, align 8
  %ptr = alloca i32*, align 8
  %k = alloca i32, align 4
  %j = alloca i32, align 4
  store i32 0, i32* %retval, align 4
  %id = getelementptr inbounds %struct.T, %struct.T* %t, i32 0, i32 0
  store i32 100, i32* %id, align 8
  %k1 = bitcast i32* %k to i8*
  call void @llvm.var.annotation(i8* %k1, i8* getelementptr inbounds ([10 x i8], [10 x i8]* @.str.1, i32 0, i32 0), i8* getelementptr inbounds ([7 x i8], [7 x i8]* @.str.2, i32 0, i32 0), i32 36)
  store i32 0, i32* %k, align 4
  %0 = load i32, i32* %k, align 4
  %add = add nsw i32 %0, 10
  store i32 %add, i32* %j, align 4
  %1 = load i32, i32* %k, align 4
  %2 = load i32, i32* %j, align 4
  %call = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([6 x i8], [6 x i8]* @.str.3, i32 0, i32 0), i32 %1, i32 %2)
  %3 = load i32, i32* %j, align 4
  %cmp = icmp slt i32 %3, 100
  br i1 %cmp, label %if.then, label %if.else

if.then:                                          ; preds = %entry
  store i32* @val1, i32** %ptr, align 8
  %funcptr = getelementptr inbounds %struct.T, %struct.T* %t, i32 0, i32 1
  store void (i32)* @g, void (i32)** %funcptr, align 8
  br label %if.end

if.else:                                          ; preds = %entry
  store i32* @val2, i32** %ptr, align 8
  %funcptr2 = getelementptr inbounds %struct.T, %struct.T* %t, i32 0, i32 1
  store void (i32)* @f, void (i32)** %funcptr2, align 8
  br label %if.end

if.end:                                           ; preds = %if.else, %if.then
  call void @dosomething(%struct.T* %t)
  %funcptr3 = getelementptr inbounds %struct.T, %struct.T* %t, i32 0, i32 1
  %4 = load void (i32)*, void (i32)** %funcptr3, align 8
  call void %4(i32 23)
  ret i32 0
}

; Function Attrs: nounwind
declare void @llvm.var.annotation(i8*, i8*, i8*, i32) #2

attributes #0 = { noinline nounwind optnone uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { nounwind }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"clang version 7.0.0 (trunk) (llvm/trunk 333727)"}
