import { Schema, Prop, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema()
export class RefreshToken extends Document {
  @Prop({ required: true, type: String })
  refresh_token!: string;
}

export const RefreshTokenSchema = SchemaFactory.createForClass(RefreshToken);
