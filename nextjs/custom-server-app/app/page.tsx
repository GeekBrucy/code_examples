"use client";

import { useEffect, useState } from "react";
import ChatForm from "../components/ChatForm";
import ChatMessage from "../components/ChatMessage";
import { socket } from "../lib/socketClient";

interface Message {
  sender: string;
  message: string;
}

export default function Home() {
  const [room, setRoom] = useState("");
  const [joined, setJoined] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [username, setUserName] = useState("");
  const handleSendMessage = (message: string) => {
    const data = { room, message, sender: username };
    setMessages((prev) => [...prev, { sender: username, message }]);
    socket.emit("message", data);
  };
  const handleJoinRoom = () => {
    if (room && username) {
      console.log("joining room");
      console.log(username);

      socket.emit("join-room", { room, username });
      setJoined(true);
    }
  };
  useEffect(() => {
    socket.on("message", (data) => {
      console.log(data);
      // setMessages((prev) => [...prev, { sender: username, message }]);
      setMessages((prev) => [...prev, data]);
    });
    socket.on("user_joined", (message) => {
      console.log(message);
      setMessages((prev) => [...prev, { sender: "system", message }]);
    });

    return () => {
      socket.off("user_joined");
      socket.off("message");
    };
  }, []);
  return (
    <div className="flex mt-24 justify-center w-full">
      {!joined ? (
        <div className="flex flex-col items-center w-full max-w-3xl mx-auto">
          <h1 className="mb-4 text-2xl font-bold">Join a Room</h1>
          <input
            type="text"
            placeholder="Enter your username"
            value={username}
            onChange={(e) => setUserName(e.target.value)}
            className="w-64 px-4 py-2 mb-4 border-2 rounded-lg"
          />
          <input
            type="text"
            placeholder="Enter room name"
            value={room}
            onChange={(e) => setRoom(e.target.value)}
            className="w-64 px-4 py-2 mb-4 border-2 rounded-lg"
          />
          <button
            onClick={handleJoinRoom}
            className="px-4 py-2 text-white bg-blue-500 rounded-lg"
          >
            Join Room
          </button>
        </div>
      ) : (
        <div className="w-full max-w-3xl mx-auto">
          <h1 className="mb-4 text-2xl font-bold">Room: {room}</h1>
          <h1 className="mb-4 text-2xl font-bold">User: {username}</h1>
          <div className="h-[500px] overflow-y-auto p-4 mb-4 bg-gray-200 border-2 rounded-lg">
            {messages.map((msg, index) => (
              <ChatMessage
                key={index}
                sender={msg.sender}
                message={msg.message}
                isOwnMessage={msg.sender === username}
                isSystemMessage={msg.sender === "system"}
              />
            ))}
          </div>
          <ChatForm onSendMessage={handleSendMessage} />
        </div>
      )}
    </div>
  );
}
