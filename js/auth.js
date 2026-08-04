function login(){


let username =
document.getElementById("username").value;


let password =
document.getElementById("password").value;



let role;



// Authentication

if(username==="admin" && password==="1234"){

role="admin";

}


else if(username==="editor" && password==="1234"){

role="editor";

}


else if(username==="viewer" && password==="1234"){

role="viewer";

}


else{


document.getElementById("message")
.innerHTML="Invalid Username or Password";


return;


}




// JWT HEADER

let header={

alg:"HS256",
type:"JWT"

};



// JWT PAYLOAD

let payload={

username:username,
role:role,
loginTime:new Date()

};



// Creating JWT like token

let token =

btoa(JSON.stringify(header))

+

"."

+

btoa(JSON.stringify(payload))

+

".signature";




// Store token

localStorage.setItem(
"jwtToken",
token
);



document.getElementById("message")
.innerHTML="Login Successful";



setTimeout(()=>{

window.location="dashboard.html";


},1000);



}