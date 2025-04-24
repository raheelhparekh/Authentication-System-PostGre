import { PrismaClient } from "@prisma/client"
const prisma=new PrismaClient

const registerUser=async(req, res)=>{
    res.send("registered")
    await prisma.user.findUnique({
        where:{email}
    })
}

export {registerUser}