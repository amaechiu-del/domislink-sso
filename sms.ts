type SmsEnv={TERMII_API_KEY?:string;TERMII_SENDER_ID?:string;TERMII_BASE_URL?:string;TERMII_CHANNEL?:string};
export async function sendSmsOtp(env:SmsEnv,phone:string,code:string){
 const key=env.TERMII_API_KEY?.trim(),sender=env.TERMII_SENDER_ID?.trim();
 if(!key||!sender)throw new Error('SMS verification is not configured yet.');
 const endpoint=new URL(env.TERMII_BASE_URL?.trim()||'https://api.ng.termii.com');
 if(endpoint.protocol!=='https:'||!endpoint.hostname.endsWith('.termii.com')||endpoint.username||endpoint.password||endpoint.port||endpoint.search||endpoint.hash)throw new Error('SMS provider endpoint is not configured correctly.');
 if(endpoint.pathname==='/'||endpoint.pathname==='/api'||endpoint.pathname==='/api/')endpoint.pathname='/api/sms/send';
 if(endpoint.pathname!=='/api/sms/send')throw new Error('SMS provider endpoint is not configured correctly.');
 const channel=env.TERMII_CHANNEL?.trim()||'dnd';
 if(!['dnd','generic'].includes(channel))throw new Error('SMS provider channel is not configured correctly.');
 if(!/^\+[1-9]\d{7,14}$/.test(phone)||!/^\d{6}$/.test(code))throw new Error('Invalid SMS verification request.');
 try{
  const response=await fetch(endpoint.toString(),{method:'POST',redirect:'manual',signal:AbortSignal.timeout(15000),headers:{'Content-Type':'application/json'},body:JSON.stringify({api_key:key,to:phone.slice(1),from:sender,sms:`Your DomisLink verification code is ${code}. It expires in 10 minutes. Do not share this code.`,type:'plain',channel})});
  if(!response.ok){await response.body?.cancel();throw new Error('provider HTTP '+response.status);}
  const payload=await response.json() as {message_id?:unknown};
  if(typeof payload?.message_id!=='string'||!payload.message_id.trim())throw new Error('provider acceptance missing');
 }catch(error){
  const reason=error instanceof Error&&/^provider HTTP \d{3}$/.test(error.message)?error.message:'provider acceptance unavailable';
  throw new Error('SMS delivery is unavailable ('+reason+').');
 }
}
