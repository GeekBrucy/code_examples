import { createServer } from "node:http";
import next from "next";
import { Server } from "socket.io";
import util from "./lib/utils.js";

const port = parseInt(process.env.PORT || "3000", 10);
const hostname = process.env.HOSTNAME || "localhost";
const dev = process.env.NODE_ENV !== "production";
const app = next({ dev, hostname, port });
const handle = app.getRequestHandler();

app.prepare().then(() => {
  const httpServer = createServer(handle);
  const io = new Server(httpServer);
  io.on("connection", (socket) => {
    console.log("User connected: ", socket.id);
    socket.on("message", ({ message, room, sender }: Message) => {
      console.log(`Message from ${sender} in room ${room}: ${message}`);
      util.SomeUtil();
      socket.to(room).emit("message", { sender, message });
    });
    socket.on("join-room", ({ room, username }) => {
      socket.join(room);
      console.log(`User ${username} joined room ${room}`);
      socket.to(room).emit("user_joined", `${username} joined room`);
    });

    socket.on("disconnect", () => {
      console.log("User disconnected: ", socket.id);
    });
  });

  httpServer.listen(port, () => {
    console.log(
      `> Server listening at http://localhost:${port} as ${
        dev ? "development" : process.env.NODE_ENV
      }`
    );
  });
});
