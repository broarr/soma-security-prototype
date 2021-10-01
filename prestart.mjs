#!/usr/bin/env zx

const { PHONE_NO, SMS_WEBHOOK } = process.env

await $`twilio phone-numbers:update ${PHONE_NO} --sms-url=${SMS_WEBHOOK}`
