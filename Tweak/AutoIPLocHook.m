// D. 在 locationd 与客户端双端抹除模拟定位标记 (isSimulatedBySoftware = NO)
        Class srcInfoCls = objc_getClass("CLLocationSourceInformation");
        if (srcInfoCls) {
            Method mSim = class_getInstanceMethod(srcInfoCls, NSSelectorFromString(@"isSimulatedBySoftware"));
            if (mSim) method_setImplementation(mSim, (IMP)hook_returnNO);
            Method mAcc = class_getInstanceMethod(srcInfoCls, NSSelectorFromString(@"isProducedByAccessory"));
            if (mAcc) method_setImplementation(mAcc, (IMP)hook_returnNO);
        }
        Class locCls = objc_getClass("CLLocation");
        if (locCls) {
            Method mLocSim = class_getInstanceMethod(locCls, NSSelectorFromString(@"isSimulatedBySoftware"));
            if (mLocSim) method_setImplementation(mLocSim, (IMP)hook_returnNO);
            Method mLocPriv = class_getInstanceMethod(locCls, NSSelectorFromString(@"_isSimulated"));
            if (mLocPriv) method_setImplementation(mLocPriv, (IMP)hook_returnNO);

            // 替换 sourceInformation 返回原生非模拟对象
            Method mSrcInfo = class_getInstanceMethod(locCls, NSSelectorFromString(@"sourceInformation"));
            if (mSrcInfo && srcInfoCls) {
                IMP cleanSrcIMP = imp_implementationWithBlock(^id(id _self) {
                    id obj = [srcInfoCls alloc];
                    SEL initSel = NSSelectorFromString(@"initWithSoftwareSimulationState:externalAccessoryState:");
                    if ([obj respondsToSelector:initSel]) {
                        NSMethodSignature *sig = [obj methodSignatureForSelector:initSel];
                        NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
                        [inv setTarget:obj];
                        [inv setSelector:initSel];
                        BOOL simState = NO;
                        BOOL accState = NO;
                        [inv setArgument:&simState atIndex:2];
                        [inv setArgument:&accState atIndex:3];
                        [inv invoke];
                        id retObj = nil;
                        [inv getReturnValue:&retObj];
                        return retObj;
                    }
                    return nil;
                });
                method_setImplementation(mSrcInfo, cleanSrcIMP);
            }
        }
