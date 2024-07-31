const http = require('node:http');
const fs = require("node:fs");
const path = require("node:path");


function parseFormDataBody(req, onResult) {
  const contentType = req.headers['content-type'];
  
  const contentLength = req.headers['content-length'];
  const boundary = contentType.split(";")[1];
  const boundaryCode = "--" + boundary.split("=")[1];

  let bodyBuffer = Buffer.alloc(0);
  req.on("data", chunk => {
    bodyBuffer = Buffer.concat([bodyBuffer, chunk]);
  });
  req.on("end", () => {
    console.log("contentLength: ", contentLength);
    console.log("body length: ", bodyBuffer.length)
    console.log("body", bodyBuffer.toString())
    
    const partsStartIndex = [];
    
    let offset = 0;
    while(offset <= bodyBuffer.length) {
      const partStartIndex = bodyBuffer.indexOf(boundaryCode, offset);
      if (partStartIndex < 0) {
        break;
      }
      partsStartIndex.push(partStartIndex);
      offset = partStartIndex + Buffer.from(boundaryCode).length;
    }
    console.log("partsStartIndex: ", partsStartIndex);
    
    const partsBuffer = [];
    for (let i = 0; i < partsStartIndex.length - 1; i++) {
      const startIndx = partsStartIndex[i];
      const endIndex = partsStartIndex[i + 1];
      partsBuffer.push(bodyBuffer.subarray(startIndx, endIndex));
    }
    console.log("🚀 ~ file: body-parse.js:41 ~ req.on ~ partsBuffer:", partsBuffer);
    
    const partList = [];
    partsBuffer.forEach(bf => {
      const part = {
        name: null,
        filename: null,
        data: "",
      };
      const dataStartIndex = bf.indexOf("\r\n\r\n");
      const dataEndIndx = bf.lastIndexOf("\r\n");

      part.data = bf.subarray(dataStartIndex + 4, dataEndIndx);
      
      const contentDisposition = bf.indexOf("\r\n", Buffer.from(boundaryCode).length + 2);
      console.log("🚀 ~ file: body-parse.js:56 ~ req.on ~ contentDisposition:", contentDisposition);
      const contentDispositionStr = bf.subarray(Buffer.from(boundaryCode).length, contentDisposition).toString();
      console.log("🚀 ~ file: body-parse.js:57 ~ req.on ~ contentDispositionStr:", contentDispositionStr);
      
      const filenameMatch = contentDispositionStr.match(/filename="([^\r\n]+)"/);
      if (filenameMatch) {
        part.filename = filenameMatch[1];
      }
      const name = contentDispositionStr.match(/name="([^\r\n"]+)"/)[1];
      part.name = name;
      partList.push(part);
    });
    
    
    partList.forEach(part => {
      if (part.filename) {
        console.log("part.data.length: ", part.data.length)
        fs.writeFileSync(path.join(__dirname, part.filename), part.data, "binary");
      }
    });
    onResult(partList);
  });
}

function parseJsonBody(req, onReuslt) {
  
  let bodyData = "";
  req.on("data", chunk => {
    console.log("🚀 ~ file: body-parse.js:85 ~ parseJsonBody ~ chunk:", chunk);
    bodyData += chunk;
  });
  req.on("end", () => {
    console.log("🚀 ~ file: body-parse.js:83 ~ parseJsonBody ~ bodyData:", bodyData);
    onReuslt(bodyData ? JSON.parse(bodyData) : null);
  });
}
function parseUrlEncodedBody(req, onReuslt) {
  
  let bodyData = "";
  req.on("data", chunk => {
    console.log("🚀 ~ file: body-parse.js:85 ~ parseUrlEncodedBody ~ chunk:", chunk);
    bodyData += chunk;
  });
  req.on("end", () => {
    console.log("🚀 ~ file: body-parse.js:83 ~ parseUrlEncodedBody ~ bodyData:", bodyData);
    onReuslt(bodyData ? Object.fromEntries(new URLSearchParams(bodyData).entries()): null);
  });
}


const server = http.createServer({ }, (req, res) => {
  console.log(req.headers);
  const contentType = req.headers['content-type'];
  if (contentType.startsWith("multipart/form-data")) {
    parseFormDataBody(req, partList => {
      console.log("🚀 ~ file: body-parse.js:45 ~ req.on ~ partList:", partList);
    });
  } else if (contentType.startsWith("application/json")) {
    parseJsonBody(req, jsonData => {
      console.log("🚀 ~ file: body-parse.js:100 ~ server ~ jsonData:", jsonData);
    });
  } else if (contentType.startsWith("application/x-www-form-urlencoded")) {
    parseUrlEncodedBody(req, urlParams => {
      console.log("🚀 ~ file: body-parse.js:100 ~ server ~ urlParams:", urlParams);
    });
  }
  
  
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    data: 'ok',
  }));
});

server.listen(8000, () => {
  console.log("listenning 8000");
});
