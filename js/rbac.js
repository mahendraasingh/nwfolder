let token =
localStorage.getItem("jwtToken");



// Check authentication

if(token==null){


window.location="index.html";


}



// Decode token


let payload =
JSON.parse(
atob(token.split(".")[1])
);



// Authorization check


if(payload.role!=="admin"){


alert(
"Unauthorized Access"
);


window.location="dashboard.html";


}




function logout(){


localStorage.removeItem("jwtToken");


window.location="index.html";


}