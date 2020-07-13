import { Schema, Prop, SchemaFactory } from "@nestjs/mongoose";
import { Document } from "mongoose";
import { TodoList } from "./user.interface";

@Schema()
export class User extends Document {
  @Prop()
  email!: string;

  @Prop()
  password!: string;

  // @Prop({
  //   type: [String],
  //   default: []
  // })
  // drafts!: string[];

  // @Prop({
  //   type: [{
  //     date: String,
  //     todos: [
  //       {
  //         title: String,
  //         completed: Boolean
  //       }
  //     ],
  //     fullyCompleted: Boolean
  //   }],
  //   default: []
  // })
  // todosLists!: TodoList[]
}

export const UserSchema = SchemaFactory.createForClass(User);
