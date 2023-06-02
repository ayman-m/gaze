import pandas as pd
import torch
import pickle
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification, Trainer, TrainingArguments, AdamW
from sklearn.preprocessing import LabelEncoder
from torch.utils.data import DataLoader


class IntentDataset(torch.utils.data.Dataset):
    def __init__(self, encodings, labels):
        self.encodings = encodings
        self.labels = labels

    def __getitem__(self, idx):
        item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
        item['labels'] = torch.tensor(self.labels[idx])
        return item

    def __len__(self):
        return len(self.labels)


def create_tokenized_dataset(train_data_path: str, test_data_path: str):

    # Load data from csv files
    train_data = pd.read_csv(train_data_path)
    test_data = pd.read_csv(test_data_path)

    # Extract sentences and labels
    train_sentences = train_data['sentences'].tolist()
    test_sentences = test_data['sentences'].tolist()

    le = LabelEncoder()
    train_labels = le.fit_transform(train_data['labels'].tolist())
    test_labels = le.transform(test_data['labels'].tolist())
    with open('models/bert/label_encoder.pkl', 'wb') as file:
        pickle.dump(le, file)
    num_labels = len(set(train_labels))

    # Initialize tokenizer
    tokenizer = DistilBertTokenizerFast.from_pretrained('distilbert-base-uncased')

    # Tokenize sentences
    train_encodings = tokenizer(train_sentences, truncation=True, padding=True, max_length=512)
    test_encodings = tokenizer(test_sentences, truncation=True, padding=True, max_length=512)

    # Convert our tokenized data into a dataset
    train_dataset = IntentDataset(train_encodings, train_labels)
    test_dataset = IntentDataset(test_encodings, test_labels)

    return train_dataset, test_dataset, num_labels


def tune_model(train_dataset, test_dataset, num_labels):

    training_args = TrainingArguments(
        output_dir='models/bert/results',  # output directory
        num_train_epochs=3,  # total number of training epochs
        per_device_train_batch_size=16,  # batch size per device during training
        per_device_eval_batch_size=64,  # batch size for evaluation
        warmup_steps=500,  # number of warmup steps for learning rate scheduler
        weight_decay=0.01,  # strength of weight decay
        logging_dir='models/bert/logs',  # directory for storing logs
        logging_steps=10,
    )
    model = DistilBertForSequenceClassification.from_pretrained("distilbert-base-uncased", num_labels=num_labels)
    # Initialize the optimizer
    optimizer = AdamW(model.parameters(), lr=1e-5)
    trainer = Trainer(
        model=model,  # the instantiated 🤗 Transformers model to be trained
        args=training_args,  # training arguments, defined above
        train_dataset=train_dataset,  # training dataset
        eval_dataset=test_dataset,  # evaluation dataset (using test dataset for evaluation)
        optimizers=(optimizer, None)
    )

    trainer.train()

    # Evaluate the model
    trainer.evaluate()

    # Save the model
    model.save_pretrained('models/bert')
    return trainer


tokenized_data = create_tokenized_dataset(train_data_path="data/processed/tuning/splits/train_data.csv",
                                          test_data_path="data/processed/tuning/splits/test_data.csv")


train_model = tune_model(train_dataset=tokenized_data[0], test_dataset=tokenized_data[1], num_labels=tokenized_data[2])