import { Document } from 'mongoose';

interface Todo {
  title: string;
  completed: boolean;
}

export interface TodoList {
  date: string;
  todos: Todo[];
  fullCompleted: boolean;
  percentComplete: number;
}

export interface User {
  email: string;
  password: string;
  organaizer: {
    todoLists: TodoList[];
  };
}
