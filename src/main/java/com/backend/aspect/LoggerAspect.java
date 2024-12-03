package com.backend.aspect;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

@Slf4j
@Aspect
@Component
public class LoggerAspect {

  // Một @Pointcut thực hiện việc gom các nhóm lại với nhau. Advice sẽ làm việc với các nhóm đã match với @Pointcut này.
  @Pointcut("execution(* com.backend..*.*(..))")
  public void springBeanPointCut() {
  }


  @Around(value = "springBeanPointCut()")
  public Object logAround(ProceedingJoinPoint joinPoint) throws Throwable {
    log.info(joinPoint.getSignature().toString() + " method execution start");
    Instant start = Instant.now();
    Object returnObj = joinPoint.proceed();
    Instant finish = Instant.now();
    long timeElapsed = Duration.between(start, finish).toMillis();
    log.info("Time took to execute " + joinPoint.getSignature().toString() + " method is : " + timeElapsed + " ms");
    log.info(joinPoint.getSignature().toString() + " method execution end");
    return returnObj;
  }

  // Phương thức này giúp Developer nắm rõ hơn về lỗi đã được throw ra trước đó. Chỉ có tác dụng với Dev, User không nhận được thông báo này.
  @AfterThrowing(value = "springBeanPointCut()", throwing = "e")
  public void logException(JoinPoint joinPoint, Exception e) {
    e.printStackTrace();
  }
}
