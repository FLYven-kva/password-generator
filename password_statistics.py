import json
import logging
import os
from datetime import datetime
import matplotlib.pyplot as plt
from pathlib import Path
from typing import Dict, Any

# Create directories for stats and data
stats_dir = Path("stats")
stats_dir.mkdir(exist_ok=True)

data_dir = Path("data")
data_dir.mkdir(exist_ok=True)

# Path to statistics file
STATS_FILE = data_dir / "password_stats.json"

def _load_stats():
    """Load statistics from file or create new stats dictionary."""
    if not STATS_FILE.exists():
        default_stats = {
            "generated": 0,
            "analyzed": 0,
            "strength": {
                "strong": 0,
                "medium": 0,
                "weak": 0
            }
        }
        with open(STATS_FILE, "w", encoding='utf-8') as f:
            json.dump(default_stats, f, indent=4)
        return default_stats
    
    try:
        with open(STATS_FILE, "r", encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logging.error(f"Error loading stats file: {str(e)}")
        return {
            "generated": 0,
            "analyzed": 0,
            "strength": {
                "strong": 0,
                "medium": 0,
                "weak": 0
            }
        }

def _save_stats(stats):
    """Save statistics to file."""
    try:
        with open(STATS_FILE, "w", encoding='utf-8') as f:
            json.dump(stats, f, indent=4)
    except Exception as e:
        logging.error(f"Error saving stats file: {str(e)}")

def log_generation(password: str) -> None:
    """
    Log generated password.
    
    Args:
        password (str): Generated password
    """
    try:
        stats = _load_stats()
        stats["generated"] = stats.get("generated", 0) + 1
        _save_stats(stats)
        logging.info(f"Password generation logged: length {len(password)}")
    except Exception as e:
        logging.error(f"Error logging password generation: {str(e)}")

def log_analysis(password: str, strength: str) -> None:
    """
    Log password analysis.
    
    Args:
        password (str): Analyzed password
        strength (str): Password strength rating
    """
    try:
        stats = _load_stats()
        stats["analyzed"] = stats.get("analyzed", 0) + 1
        stats["strength"][strength] = stats["strength"].get(strength, 0) + 1
        _save_stats(stats)
        logging.info(f"Password analysis logged: strength {strength}")
    except Exception as e:
        logging.error(f"Error logging password analysis: {str(e)}")

def get_statistics() -> Dict[str, Any]:
    """
    Get overall password statistics.
    
    Returns:
        Dict[str, Any]: Dictionary with statistics
    """
    try:
        stats = _load_stats()
        return {
            "generated": stats.get("generated", 0),
            "analyzed": stats.get("analyzed", 0),
            "strength": stats.get("strength", {
                "strong": 0,
                "medium": 0,
                "weak": 0
            })
        }
    except Exception as e:
        logging.error(f"Error getting statistics: {str(e)}")
        return {
            "generated": 0,
            "analyzed": 0,
            "strength": {
                "strong": 0,
                "medium": 0,
                "weak": 0
            }
        }

def visualize_statistics() -> None:
    """
    Create password statistics visualizations in separate windows.
    """
    try:
        stats = get_statistics()
        
        # Password strength distribution plot
        plt.figure(figsize=(10, 6))
        strengths = ["Strong", "Medium", "Weak"]
        counts = [
            stats["strength"].get("strong", 0),
            stats["strength"].get("medium", 0),
            stats["strength"].get("weak", 0)
        ]
        
        plt.bar(strengths, counts)
        plt.title("Password Strength Distribution")
        plt.xlabel("Strength")
        plt.ylabel("Count")
        
        # Add values above bars
        for i, count in enumerate(counts):
            plt.text(i, count, str(count), ha='center', va='bottom')
        
        plt.show()
        
        # Overall statistics plot
        plt.figure(figsize=(10, 6))
        categories = ["Generated", "Analyzed"]
        values = [stats["generated"], stats["analyzed"]]
        
        plt.bar(categories, values)
        plt.title("Overall Password Statistics")
        plt.ylabel("Count")
        
        # Add values above bars
        for i, value in enumerate(values):
            plt.text(i, value, str(value), ha='center', va='bottom')
        
        plt.show()
        
        logging.info("Statistics visualization completed")
    except Exception as e:
        logging.error(f"Error visualizing statistics: {str(e)}")
        raise

def encrypt_stats(password):
    """
    Encrypt statistics file for security (placeholder).
    
    Args:
        password (str): Password for encryption
    """
    # This would implement actual encryption in a real system
    logging.info("Stats file encryption feature is not implemented yet")

def decrypt_stats(password):
    """
    Decrypt statistics file (placeholder).
    
    Args:
        password (str): Password for decryption
    """
    # This would implement actual decryption in a real system
    logging.info("Stats file decryption feature is not implemented yet")

if __name__ == "__main__":
    # Example usage
    log_generation("example_password")
    log_analysis("example_password", "strong")
    stats = get_statistics()
    print("Password statistics:", stats)
    visualize_statistics() 