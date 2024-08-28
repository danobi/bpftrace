; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@ringbuf = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@event_loss_counter = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !16
@stack = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !36

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !54 {
entry:
  %key = alloca i32, align 4
  %perfdata = alloca i64, align 8
  %arraycmp.result = alloca i1, align 1
  %v2 = alloca i32, align 4
  %v1 = alloca i32, align 4
  %"$b" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$b")
  store i64 0, ptr %"$b", align 8
  %"$a" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$a")
  store i64 0, ptr %"$a", align 8
  %1 = getelementptr i64, ptr %0, i64 14
  %arg0 = load volatile i64, ptr %1, align 8
  %2 = add i64 %arg0, 0
  store i64 %2, ptr %"$a", align 8
  %3 = getelementptr i64, ptr %0, i64 14
  %arg01 = load volatile i64, ptr %3, align 8
  %4 = add i64 %arg01, 0
  store i64 %4, ptr %"$b", align 8
  %5 = load i64, ptr %"$a", align 8
  %6 = load i64, ptr %"$b", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %v1)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %v2)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %arraycmp.result)
  store i1 true, ptr %arraycmp.result, align 1
  %7 = inttoptr i64 %5 to ptr
  %8 = inttoptr i64 %6 to ptr
  %9 = getelementptr [4 x i32], ptr %7, i32 0, i32 0
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %v1, i32 4, ptr %9)
  %10 = load i32, ptr %v1, align 4
  %11 = getelementptr [4 x i32], ptr %8, i32 0, i32 0
  %probe_read_kernel2 = call i64 inttoptr (i64 113 to ptr)(ptr %v2, i32 4, ptr %11)
  %12 = load i32, ptr %v2, align 4
  %arraycmp.cmp = icmp ne i32 %10, %12
  br i1 %arraycmp.cmp, label %arraycmp.false, label %arraycmp.loop

if_body:                                          ; preds = %arraycmp.done
  call void @llvm.lifetime.start.p0(i64 -1, ptr %perfdata)
  store i64 30000, ptr %perfdata, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %perfdata, i64 8, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

if_end:                                           ; preds = %deadcode, %arraycmp.done
  ret i64 0

arraycmp.false:                                   ; preds = %arraycmp.loop7, %arraycmp.loop3, %arraycmp.loop, %entry
  store i1 false, ptr %arraycmp.result, align 1
  br label %arraycmp.done

arraycmp.done:                                    ; preds = %arraycmp.false, %arraycmp.loop11
  %13 = load i1, ptr %arraycmp.result, align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %arraycmp.result)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %v1)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %v2)
  %14 = zext i1 %13 to i64
  %true_cond = icmp ne i64 %14, 0
  br i1 %true_cond, label %if_body, label %if_end

arraycmp.loop:                                    ; preds = %entry
  %15 = getelementptr [4 x i32], ptr %7, i32 0, i32 1
  %probe_read_kernel4 = call i64 inttoptr (i64 113 to ptr)(ptr %v1, i32 4, ptr %15)
  %16 = load i32, ptr %v1, align 4
  %17 = getelementptr [4 x i32], ptr %8, i32 0, i32 1
  %probe_read_kernel5 = call i64 inttoptr (i64 113 to ptr)(ptr %v2, i32 4, ptr %17)
  %18 = load i32, ptr %v2, align 4
  %arraycmp.cmp6 = icmp ne i32 %16, %18
  br i1 %arraycmp.cmp6, label %arraycmp.false, label %arraycmp.loop3

arraycmp.loop3:                                   ; preds = %arraycmp.loop
  %19 = getelementptr [4 x i32], ptr %7, i32 0, i32 2
  %probe_read_kernel8 = call i64 inttoptr (i64 113 to ptr)(ptr %v1, i32 4, ptr %19)
  %20 = load i32, ptr %v1, align 4
  %21 = getelementptr [4 x i32], ptr %8, i32 0, i32 2
  %probe_read_kernel9 = call i64 inttoptr (i64 113 to ptr)(ptr %v2, i32 4, ptr %21)
  %22 = load i32, ptr %v2, align 4
  %arraycmp.cmp10 = icmp ne i32 %20, %22
  br i1 %arraycmp.cmp10, label %arraycmp.false, label %arraycmp.loop7

arraycmp.loop7:                                   ; preds = %arraycmp.loop3
  %23 = getelementptr [4 x i32], ptr %7, i32 0, i32 3
  %probe_read_kernel12 = call i64 inttoptr (i64 113 to ptr)(ptr %v1, i32 4, ptr %23)
  %24 = load i32, ptr %v1, align 4
  %25 = getelementptr [4 x i32], ptr %8, i32 0, i32 3
  %probe_read_kernel13 = call i64 inttoptr (i64 113 to ptr)(ptr %v2, i32 4, ptr %25)
  %26 = load i32, ptr %v2, align 4
  %arraycmp.cmp14 = icmp ne i32 %24, %26
  br i1 %arraycmp.cmp14, label %arraycmp.false, label %arraycmp.loop11

arraycmp.loop11:                                  ; preds = %arraycmp.loop7
  br label %arraycmp.done

event_loss_counter:                               ; preds = %if_body
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key)
  store i32 0, ptr %key, align 4
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %if_body
  call void @llvm.lifetime.end.p0(i64 -1, ptr %perfdata)
  ret i64 0

lookup_success:                                   ; preds = %event_loss_counter
  %27 = atomicrmw add ptr %lookup_elem, i64 1 seq_cst, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge

deadcode:                                         ; No predecessors!
  br label %if_end
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!51}
!llvm.module.flags = !{!53}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !4)
!4 = !{!5, !11}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 27, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 262144, lowerBound: 0)
!16 = !DIGlobalVariableExpression(var: !17, expr: !DIExpression())
!17 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!18 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !19)
!19 = !{!20, !25, !30, !33}
!20 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !21, size: 64)
!21 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!22 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !23)
!23 = !{!24}
!24 = !DISubrange(count: 2, lowerBound: 0)
!25 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !26, size: 64, offset: 64)
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !28)
!28 = !{!29}
!29 = !DISubrange(count: 1, lowerBound: 0)
!30 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !31, size: 64, offset: 128)
!31 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !32, size: 64)
!32 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!33 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !34, size: 64, offset: 192)
!34 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !35, size: 64)
!35 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!36 = !DIGlobalVariableExpression(var: !37, expr: !DIExpression())
!37 = distinct !DIGlobalVariable(name: "stack", linkageName: "global", scope: !2, file: !2, type: !38, isLocal: false, isDefinition: true)
!38 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !39)
!39 = !{!40, !25, !30, !45}
!40 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !41, size: 64)
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !42, size: 64)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !43)
!43 = !{!44}
!44 = !DISubrange(count: 6, lowerBound: 0)
!45 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !46, size: 64, offset: 192)
!46 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !47, size: 64)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !48, size: 32768, elements: !49)
!48 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!49 = !{!50}
!50 = !DISubrange(count: 4096, lowerBound: 0)
!51 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !52)
!52 = !{!0, !16, !36}
!53 = !{i32 2, !"Debug Info Version", i32 3}
!54 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !55, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !51, retainedNodes: !58)
!55 = !DISubroutineType(types: !56)
!56 = !{!35, !57}
!57 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !48, size: 64)
!58 = !{!59}
!59 = !DILocalVariable(name: "ctx", arg: 1, scope: !54, file: !2, type: !57)
