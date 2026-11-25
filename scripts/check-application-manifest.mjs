import {readFileSync} from "node:fs";
import {validateManifest} from "../sdk/application-manifest.mjs";
try{
 if(!process.argv[2])throw Error("Provide application manifest path");
 const manifest=validateManifest(JSON.parse(readFileSync(process.argv[2],"utf8")));
 console.log(JSON.stringify({status:"validated",application_id:manifest.application_id,environment:manifest.environment,registration:"not_performed"},null,2));
}catch{
 console.error("Application manifest validation failed; review required fields and environment.");
 process.exitCode=1;
}
