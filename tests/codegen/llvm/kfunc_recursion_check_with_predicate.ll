; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%"struct map_t.3" = type { ptr, ptr, ptr, ptr }
%print_integer_8_t = type <{ i64, i64, [8 x i8] }>

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@recursion_prevention = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !22
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !36
@stack = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !45
@fmt_string_args = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !55

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kfunc_queued_spin_lock_slowpath_1(ptr %0) section "s_kfunc_queued_spin_lock_slowpath_1" !dbg !67 {
entry:
  %lookup_key19 = alloca i32, align 4
  %key13 = alloca i32, align 4
  %lookup_fmtstr_key = alloca i32, align 4
  %lookup_key6 = alloca i32, align 4
  %key = alloca i32, align 4
  %lookup_key = alloca i32, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_key)
  store i32 0, ptr %lookup_key, align 4
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @recursion_prevention, ptr %lookup_key)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_key)
  %cast = ptrtoint ptr %lookup_elem to i64
  %1 = atomicrmw xchg i64 %cast, i64 1 seq_cst, align 8
  %value_set_condition = icmp eq i64 %1, 0
  br i1 %value_set_condition, label %lookup_merge, label %value_is_set

lookup_failure:                                   ; preds = %entry
  ret i64 0

lookup_merge:                                     ; preds = %lookup_success
  %get_pid_tgid = call i64 inttoptr (i64 14 to ptr)()
  %2 = lshr i64 %get_pid_tgid, 32
  %3 = icmp eq i64 %2, 1234
  %4 = zext i1 %3 to i64
  %predcond = icmp eq i64 %4, 0
  br i1 %predcond, label %pred_false, label %pred_true

value_is_set:                                     ; preds = %lookup_success
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key)
  store i32 0, ptr %key, align 4
  %lookup_elem1 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key)
  %map_lookup_cond5 = icmp ne ptr %lookup_elem1, null
  br i1 %map_lookup_cond5, label %lookup_success2, label %lookup_failure3

lookup_success2:                                  ; preds = %value_is_set
  %5 = atomicrmw add ptr %lookup_elem1, i64 1 seq_cst, align 8
  br label %lookup_merge4

lookup_failure3:                                  ; preds = %value_is_set
  br label %lookup_merge4

lookup_merge4:                                    ; preds = %lookup_failure3, %lookup_success2
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  ret i64 0

pred_false:                                       ; preds = %lookup_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_key6)
  store i32 0, ptr %lookup_key6, align 4
  %lookup_elem7 = call ptr inttoptr (i64 1 to ptr)(ptr @recursion_prevention, ptr %lookup_key6)
  %map_lookup_cond11 = icmp ne ptr %lookup_elem7, null
  br i1 %map_lookup_cond11, label %lookup_success8, label %lookup_failure9

pred_true:                                        ; preds = %lookup_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_fmtstr_key)
  store i32 0, ptr %lookup_fmtstr_key, align 4
  %lookup_fmtstr_map = call ptr inttoptr (i64 1 to ptr)(ptr @fmt_string_args, ptr %lookup_fmtstr_key)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_fmtstr_key)
  %lookup_fmtstr_cond = icmp ne ptr %lookup_fmtstr_map, null
  br i1 %lookup_fmtstr_cond, label %lookup_fmtstr_merge, label %lookup_fmtstr_failure

lookup_success8:                                  ; preds = %pred_false
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_key6)
  %cast12 = ptrtoint ptr %lookup_elem7 to i64
  store i64 0, i64 %cast12, align 8
  br label %lookup_merge10

lookup_failure9:                                  ; preds = %pred_false
  br label %lookup_merge10

lookup_merge10:                                   ; preds = %lookup_failure9, %lookup_success8
  ret i64 0

lookup_fmtstr_failure:                            ; preds = %pred_true
  ret i64 0

lookup_fmtstr_merge:                              ; preds = %pred_true
  %6 = getelementptr %print_integer_8_t, ptr %lookup_fmtstr_map, i64 0, i32 0
  store i64 30007, ptr %6, align 8
  %7 = getelementptr %print_integer_8_t, ptr %lookup_fmtstr_map, i64 0, i32 1
  store i64 0, ptr %7, align 8
  %8 = getelementptr %print_integer_8_t, ptr %lookup_fmtstr_map, i32 0, i32 2
  call void @llvm.memset.p0.i64(ptr align 1 %8, i8 0, i64 8, i1 false)
  store i64 2, ptr %8, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %lookup_fmtstr_map, i64 24, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %lookup_fmtstr_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key13)
  store i32 0, ptr %key13, align 4
  %lookup_elem14 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key13)
  %map_lookup_cond18 = icmp ne ptr %lookup_elem14, null
  br i1 %map_lookup_cond18, label %lookup_success15, label %lookup_failure16

counter_merge:                                    ; preds = %lookup_merge17, %lookup_fmtstr_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_key19)
  store i32 0, ptr %lookup_key19, align 4
  %lookup_elem20 = call ptr inttoptr (i64 1 to ptr)(ptr @recursion_prevention, ptr %lookup_key19)
  %map_lookup_cond24 = icmp ne ptr %lookup_elem20, null
  br i1 %map_lookup_cond24, label %lookup_success21, label %lookup_failure22

lookup_success15:                                 ; preds = %event_loss_counter
  %9 = atomicrmw add ptr %lookup_elem14, i64 1 seq_cst, align 8
  br label %lookup_merge17

lookup_failure16:                                 ; preds = %event_loss_counter
  br label %lookup_merge17

lookup_merge17:                                   ; preds = %lookup_failure16, %lookup_success15
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key13)
  br label %counter_merge

lookup_success21:                                 ; preds = %counter_merge
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_key19)
  %cast25 = ptrtoint ptr %lookup_elem20 to i64
  store i64 0, i64 %cast25, align 8
  br label %lookup_merge23

lookup_failure22:                                 ; preds = %counter_merge
  br label %lookup_merge23

lookup_merge23:                                   ; preds = %lookup_failure22, %lookup_success21
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }

!llvm.dbg.cu = !{!64}
!llvm.module.flags = !{!66}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "recursion_prevention", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !19}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 6, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 1, lowerBound: 0)
!16 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !17, size: 64, offset: 128)
!17 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!18 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!19 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !20, size: 64, offset: 192)
!20 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !21, size: 64)
!21 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !25)
!25 = !{!26, !31}
!26 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !27, size: 64)
!27 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !28, size: 64)
!28 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !29)
!29 = !{!30}
!30 = !DISubrange(count: 27, lowerBound: 0)
!31 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !32, size: 64, offset: 64)
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !34)
!34 = !{!35}
!35 = !DISubrange(count: 262144, lowerBound: 0)
!36 = !DIGlobalVariableExpression(var: !37, expr: !DIExpression())
!37 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !38, isLocal: false, isDefinition: true)
!38 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !39)
!39 = !{!40, !11, !16, !19}
!40 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !41, size: 64)
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !42, size: 64)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !43)
!43 = !{!44}
!44 = !DISubrange(count: 2, lowerBound: 0)
!45 = !DIGlobalVariableExpression(var: !46, expr: !DIExpression())
!46 = distinct !DIGlobalVariable(name: "stack", linkageName: "global", scope: !2, file: !2, type: !47, isLocal: false, isDefinition: true)
!47 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !48)
!48 = !{!5, !11, !16, !49}
!49 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !50, size: 64, offset: 192)
!50 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !51, size: 64)
!51 = !DICompositeType(tag: DW_TAG_array_type, baseType: !52, size: 32768, elements: !53)
!52 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!53 = !{!54}
!54 = !DISubrange(count: 4096, lowerBound: 0)
!55 = !DIGlobalVariableExpression(var: !56, expr: !DIExpression())
!56 = distinct !DIGlobalVariable(name: "fmt_string_args", linkageName: "global", scope: !2, file: !2, type: !57, isLocal: false, isDefinition: true)
!57 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !58)
!58 = !{!5, !11, !16, !59}
!59 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !60, size: 64, offset: 192)
!60 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !61, size: 64)
!61 = !DICompositeType(tag: DW_TAG_array_type, baseType: !52, size: 192, elements: !62)
!62 = !{!63}
!63 = !DISubrange(count: 24, lowerBound: 0)
!64 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !65)
!65 = !{!0, !22, !36, !45, !55}
!66 = !{i32 2, !"Debug Info Version", i32 3}
!67 = distinct !DISubprogram(name: "kfunc_queued_spin_lock_slowpath_1", linkageName: "kfunc_queued_spin_lock_slowpath_1", scope: !2, file: !2, type: !68, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !64, retainedNodes: !71)
!68 = !DISubroutineType(types: !69)
!69 = !{!21, !70}
!70 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !52, size: 64)
!71 = !{!72}
!72 = !DILocalVariable(name: "ctx", arg: 1, scope: !67, file: !2, type: !70)
