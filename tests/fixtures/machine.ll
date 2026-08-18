; ModuleID = '/tmp/ir-probe/machine.c'
source_filename = "/tmp/ir-probe/machine.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.conn = type { i32 }

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @step(ptr noundef %0, i32 noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca i32, align 4
  store ptr %0, ptr %3, align 8
  store i32 %1, ptr %4, align 4
  %5 = load ptr, ptr %3, align 8
  %6 = getelementptr inbounds %struct.conn, ptr %5, i32 0, i32 0
  %7 = load i32, ptr %6, align 4
  switch i32 %7, label %24 [
    i32 0, label %8
    i32 1, label %11
    i32 2, label %21
  ]

8:                                                ; preds = %2
  %9 = load ptr, ptr %3, align 8
  %10 = getelementptr inbounds %struct.conn, ptr %9, i32 0, i32 0
  store i32 1, ptr %10, align 4
  br label %24

11:                                               ; preds = %2
  %12 = load i32, ptr %4, align 4
  %13 = icmp sgt i32 %12, 0
  br i1 %13, label %14, label %17

14:                                               ; preds = %11
  %15 = load ptr, ptr %3, align 8
  %16 = getelementptr inbounds %struct.conn, ptr %15, i32 0, i32 0
  store i32 2, ptr %16, align 4
  br label %20

17:                                               ; preds = %11
  %18 = load ptr, ptr %3, align 8
  %19 = getelementptr inbounds %struct.conn, ptr %18, i32 0, i32 0
  store i32 0, ptr %19, align 4
  br label %20

20:                                               ; preds = %17, %14
  br label %24

21:                                               ; preds = %2
  %22 = load ptr, ptr %3, align 8
  %23 = getelementptr inbounds %struct.conn, ptr %22, i32 0, i32 0
  store i32 0, ptr %23, align 4
  br label %24

24:                                               ; preds = %2, %21, %20, %8
  ret void
}

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"Ubuntu clang version 18.1.3 (1ubuntu1)"}
